package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jasonlvhit/gocron"
)

type Handler interface {
	Init(client kubernetes.Interface, config *rest.Config) error
	ObjectCreated(client kubernetes.Interface, obj interface{})
	ObjectDeleted(client kubernetes.Interface, obj interface{})
	ObjectUpdated(client kubernetes.Interface, objOld, objNew interface{})
}

type HandlerImpl struct {
	refreshSchedule int
	tenantId        string
	clientId        string
	clientSecret    string
	subscriptionId  string
	mutex           *sync.RWMutex
}

type AuthToken struct {
	AccessToken string `json:"access_token"`
}

type ImageVulnerability struct {
	Value []Vulnerability `json:"value"`
}

type Vulnerability struct {
	Id         string `json:"id"`
	Properties struct {
		AdditionalData struct {
			RegistryHost   string `json:"registryHost"`
			RepositoryName string `json:"repositoryName"`
			ImageDigest    string `json:"imageDigest"`
		} `json:"additionalData"`
		Status struct {
			Severity string `json:"severity"`
		}
	} `json:"properties"`
}

var digests = make(map[string][]Vulnerability)

func (t *HandlerImpl) Init(client kubernetes.Interface, config *rest.Config) error {
	logrus.Debug("HandlerImpl.Init")

	result := getConfig("/config/imagescan/acr-kube-image-scan-config.yaml", "./config.yaml")
	if result == nil {
		logrus.Warnf("Cannot read config.yaml")
		return nil
	} else {
		i, _ := strconv.Atoi(result["refreshSchedule"])
		t.refreshSchedule = i
		t.tenantId = result["tenantId"]
		t.clientId = result["clientId"]
		t.clientSecret = result["clientSecret"]
		t.subscriptionId = result["subscriptionId"]
		t.mutex = &sync.RWMutex{}
	}

	invokeApi(t)
	go refreshVulnerabilities(t)

	return nil
}

func getConfig(path, path2 string) map[string]string {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		file, err = ioutil.ReadFile(path2)
		if err != nil {
			logrus.Warnf("Cannot read configuration file")
			return nil
		}
	}

	var result map[string]string
	err = json.Unmarshal([]byte(file), &result)

	if err != nil {
		logrus.Warnf("Invalid JSON configuration file")
		return nil
	}
	return result
}

func refreshVulnerabilities(t *HandlerImpl) {
	//TODO - Changet the hardcoded value to config
	gocron.Every(uint64(t.refreshSchedule)).Minutes().Do(invokeApi, t)
	<-gocron.Start()
}

func invokeApi(t *HandlerImpl) {

	accessToken := GetAccessToken(t)

	logrus.Debug("Invoking ASC API")

	ascUri := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/subAssessments?api-version=2019-01-01-preview&NextLink=_legacy", t.subscriptionId)
	var bearer = "Bearer " + accessToken

	armClient := http.Client{
		Timeout: time.Second * 30, // Timeout after 30 seconds
	}

	req, err := http.NewRequest(http.MethodGet, ascUri, nil)
	if err != nil {
		logrus.Fatal(err)
	}
	req.Header.Add("Authorization", bearer)

	res, getErr := armClient.Do(req)
	if getErr != nil {
		logrus.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		logrus.Fatal(readErr)
	}

	var vulnerabilities ImageVulnerability
	jsonErr := json.Unmarshal(body, &vulnerabilities)
	if jsonErr != nil {
		logrus.Fatal(jsonErr)
	}

	logrus.Debug("Waiting for write lock")
	t.mutex.Lock()
	logrus.Debug("Acquired write lock")

	for item := range digests {
		delete(digests, item)
	}

	//var digests = make(map[string][]Vulnerability)
	for _, v := range vulnerabilities.Value {
		digests[v.Properties.AdditionalData.ImageDigest] = append(digests[v.Properties.AdditionalData.ImageDigest], v)
	}
	t.mutex.Unlock()
	//t.ctrl.WriteCh <- digests
	logrus.Debug("Vulnerability data refreshed")
}

func GetAccessToken(t *HandlerImpl) (accessToken string) {
	logrus.Debug("Getting Access Token")

	tokenUri := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", t.tenantId)

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {t.clientId},
		"client_secret": {t.clientSecret},
		"resource":      {"https://management.azure.com/"},
	}

	res, err := http.PostForm(tokenUri, formData)
	if err != nil {
		logrus.Fatal(err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		logrus.Fatal(readErr)
	}

	var authToken AuthToken
	jsonErr := json.Unmarshal(body, &authToken)
	if jsonErr != nil {
		logrus.Fatal(jsonErr)
	}

	return authToken.AccessToken
}

func (t *HandlerImpl) ObjectCreated(client kubernetes.Interface, obj interface{}) {
	pod := obj.(*core_v1.Pod)
	logrus.Debug("HandlerImpl.ObjectCreated")

	logrus.Debugf("Pod: %s v.%s (Node: %s, %s)", pod.Name, pod.ObjectMeta.ResourceVersion,
		pod.Spec.NodeName, pod.Status.Phase)

	for _, status := range pod.Status.ContainerStatuses {
		imageDigest := status.ImageID

		logrus.Debugf("Container: %s, Digest: %s", status.Image, imageDigest)

		idx := strings.LastIndex(status.ImageID, "sha256:")
		digestId := status.ImageID[idx:]
		logrus.Debugf("Digest: %s", digestId)

		t.mutex.RLock()
		digest, ok := digests[digestId]
		t.mutex.RUnlock()

		if ok {
			ProcessFindings(t, pod, digest, status.ImageID)
		}
	}
}

func ProcessFindings(t *HandlerImpl, pod *core_v1.Pod, digest []Vulnerability, imageId string) {
	issues := make(map[string][]Vulnerability)

	for _, v := range digest {
		if v.Properties.Status.Severity == "High" {
			issues["High"] = append(issues["High"], v)
		} else if v.Properties.Status.Severity == "Medium" {
			issues["Medium"] = append(issues["Medium"], v)
		} else {
			issues["Low"] = append(issues["Low"], v)
		}
	}

	logrus.Printf("Vulnerability Report for Image: %s", imageId)
	logrus.Printf("Pod: %s v.%s (Node: %s, %s)", pod.Name, pod.ObjectMeta.ResourceVersion,
		pod.Spec.NodeName, pod.Status.Phase)
	logrus.Printf("Issues identified High: %d Medium: %d Low: %d", len(issues["High"]), len(issues["Medium"]), len(issues["Low"]))

	idx := strings.LastIndex(digest[0].Id, "Microsoft.Security/assessments/")
	assessmentKey := digest[0].Id[idx+31 : idx+67]
	logrus.Printf("Refer detailed report at https://ms.portal.azure.com/#blade/Microsoft_Azure_Security/ContainerRegistryRecommendationDetailsBlade/assessmentKey/%s", assessmentKey)
}

// ObjectDeleted is called when an object is deleted
func (t *HandlerImpl) ObjectDeleted(client kubernetes.Interface, obj interface{}) {
	logrus.Debug("HandlerImpl.ObjectDeleted")
}

// ObjectUpdated is called when an object is updated
func (t *HandlerImpl) ObjectUpdated(client kubernetes.Interface, objOld, objNew interface{}) {
	logrus.Debug("HandlerImpl.ObjectUpdated")
}
