package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
)

func getClient() (kubernetes.Interface, *rest.Config) {

	var client kubernetes.Interface

	clusterConfig, err := rest.InClusterConfig()
	if err == nil {
		client, err := kubernetes.NewForConfig(clusterConfig)
		if err == nil {
			return client, clusterConfig
		}
	}

	if err != nil {
		logrus.Warnf("Get in-cluster config: %v", err)
	}

	// construct the path to resolve to `~/.kube/config`
	kubeConfigPath := os.Getenv("HOME") + "/.kube/config"

	// create the config from the path
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		logrus.Fatalf("getClusterConfig: %v", err)
		// generate the client based off of the config
	}

	// generate the client based off of the config
	client, err = kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Fatalf("getClusterConfig: %v", err)
	}

	logrus.Debug("Successfully constructed k8s client")
	return client, config
}

func setLogLevel() {
	lv, ok := os.LookupEnv("SCANNER_LOG_LEVEL")

	if !ok {
		return
	}
	switch strings.ToUpper(strings.TrimSpace(lv)) {
	case "DEBUG":
		logrus.SetLevel(logrus.DebugLevel)
	case "INFO":
		logrus.SetLevel(logrus.InfoLevel)
	case "WARN":
		logrus.SetLevel(logrus.WarnLevel)
	case "ERROR":
		logrus.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		logrus.SetLevel(logrus.FatalLevel)
	case "PANIC":
		logrus.SetLevel(logrus.PanicLevel)
	default:
		logrus.Warnf("Unrecognized log level '%s'; recognized log levels are DEBUG, INFO, WARN, ERROR, FATAL, PANIC", lv)
	}
}

func main() {

	//defer profile.Start(profile.MemProfile).Stop()

	setLogLevel()

	client, config := getClient()

	lv, ok := os.LookupEnv("SYNC_IN_MINUTES")
	syncMin := "24h"
	min, _ := time.ParseDuration(syncMin)
	if ok {
		syncMin = lv
		minConfig, err := time.ParseDuration(syncMin)
		if err != nil {
			logrus.Warnf("Invalid configuration for SYNC_IN_MINUTES")
		} else {
			min = minConfig
		}
	}

	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options meta_v1.ListOptions) (runtime.Object, error) {
				return client.CoreV1().Pods(meta_v1.NamespaceAll).List(context.TODO(), options)
			},
			WatchFunc: func(options meta_v1.ListOptions) (watch.Interface, error) {
				return client.CoreV1().Pods(meta_v1.NamespaceAll).Watch(context.TODO(), options)
			},
		},
		&api_v1.Pod{},
		time.Duration(min.Nanoseconds()),
		cache.Indexers{},
	)

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			logrus.Debugf("Add pod: %s", key)
			//logrus.Debugf("Add pod: %s", key)
			if err == nil {
				enqueuePod(obj, queue, true)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			logrus.Debugf("Update pod: %s", key)
			if err == nil {
				store := informer.GetStore()
				store = store
				enqueuePod(new, queue, true)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			logrus.Debugf("Delete pod: %s", key)
			if err == nil {
				enqueuePod(obj, queue, false)
			}
		},
	})

	handler := &HandlerImpl{}
	if handler.Init(client, config) != nil {
		os.Exit(1)
	}

	controller := Controller{
		logger:    logrus.NewEntry(logrus.New()),
		clientset: client,
		informer:  informer,
		queue:     queue,
		handler:   handler,
	}

	// use a channel to synchronize the finalization for a graceful shutdown
	stopCh := make(chan struct{})
	defer close(stopCh)

	// run the controller loop to process items
	go controller.Run(stopCh)

	// use a channel to handle OS signals to terminate and gracefully shut
	// down processing
	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, syscall.SIGTERM)
	signal.Notify(sigTerm, syscall.SIGINT)
	<-sigTerm
}

func enqueuePod(obj interface{}, queue workqueue.RateLimitingInterface, includeOnlyRunning bool) bool {
	pod := obj.(*api_v1.Pod)
	//Filter pending pods
	if includeOnlyRunning && pod.Status.Phase != api_v1.PodRunning {
		return false
	}
	copy := pod.DeepCopy()
	queue.Add(copy)
	return true
}
