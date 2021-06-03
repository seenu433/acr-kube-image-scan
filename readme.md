# ACR Kube Image Scanner

Any image pushed into Azure Container Registry (ACR) with Azure Defender for Container Registries enabled, will be scanned for vulnerabilities and the report is made available in Security Center.

With this integration, static image scanning is achieved but there is no provision to know if any of the vulnerable images are currently running in a kubernetes cluster. Moreover an image which is healthy during deployment can become unhealthy as new CVE are published.

It is equally important to have a mechanism to be notified of any unhealthy images running in the kubernetes cluster on a realtime basis and if possible an ability to block deployment or scale down the replicas.

The ACR Kube Image Scan controller watches the pods and notify if the container image is unhealthy. Below are the features currently implemented:

- Loads the vulnerability report from ASC on a regular interval
- Monitors for Pod creations
- Checks if the container image has any identified vulnerabilities
- Logs the Pod/Image details with the count of vulnerabilities
- Validates all the pods on a schedule as a backup to any misses

### Deployment Instructions

#### Prerequisites

- Create an [Azure Container Registry](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-get-started-portal)
- Enable [Azure Defender for Container Registries](https://docs.microsoft.com/en-us/azure/security-center/defender-for-container-registries-usage) on ACR
- Create an [AKS cluster with ACR integration](https://docs.microsoft.com/en-us/azure/aks/cluster-container-registry-integration#create-a-new-aks-cluster-with-acr-integration)

#### Image Scanner Deployment

Create a service principal to access the Security Center assessment report and grant read-only role to the subscription

```azurecli
az ad sp create-for-rbac -n "acr-kube-image-scan" --role Reader --scopes /subscriptions/{SubID}
```

Make a note of the appId, password and tenant

Clone the repository

```bash
git clone https://github.com/seenu433/acr-kube-image-scan
cd acr-kube-image-scan
```

Build the docker images

```bash
docker build -t <registry-name>.azurecr.io/acr-kube-image-scan:latest .
docker push <registry-name>.azurecr.io/acr-kube-image-scan:latest
```

Create the kubernetes secret with the configuration

```bash
# update the values in src/config.yaml

# Create the config as a secret
kubectl create secret generic acr-kube-image-scan-config --from-file=acr-kube-image-scan-config.yaml=./src/config.yaml
```

Sample configuration

```json
{
  "refreshSchedule": "10",
  "tenantId": "--guid-value--",
  "clientId": "--guid-value--",
  "clientSecret": "xxxxxxxxx",
  "subscriptionId": "--guid-value--"
}
```

Deploy the scanner

```bash
# Update the registry name in the deployment.yaml

kubectl apply -f deployment.yaml
```

The deployment can be updated for the below configuration through environment variables

- SCANNER_LOG_LEVEL - ex. DEBUG, INFO
- SYNC_IN_MINUTES - interval to re-check all the deployed pods against the vulnerability metadata

Check the logs for the output. sample output below:

```dotnetcli
time="2021-06-02T21:22:17Z" level=info msg="Vulnerability Report for Image: xxx.azurecr.io/fasthack-api@sha256:aa47376efcf2175e9b2b6fe1585c171c463bc31a76b7b8b8b10fa0d17e983c82"
time="2021-06-02T21:22:17Z" level=info msg="Pod: frontend-deployment-77fb59cc8f-fln29 v.1623409 (Node: aks-agentpool-32230951-vmss000000, Running)"
time="2021-06-02T21:22:17Z" level=info msg="Issues identified High: 0 Medium: 16 Low: 0\n"
time="2021-06-02T21:22:17Z" level=info msg="Refer detailed report at https://ms.portal.azure.com/#blade/Microsoft_Azure_Security/ContainerRegistryRecommendationDetailsBlade/assessmentKey/xxxxxxxxxxxx"
```

#### Local setup

- Open the cloned repo in vscode with go extension
- Update the config.yaml in the src folder for the service principal details
- Open the terminal
- Set the env variables
  - set HOME=C:/Users/{username}
  - set SCANNER_LOG_LEVEL=DEBUG
  - set SYNC_IN_MINUTES=2m
- Change the directory to src *cd src*
- Build the program *go build*
- Run the program *go run .*

#### Next steps

- Ability to send notifications through channels like Teams etc.
- Ability to act on the deployment like delete/scale down etc.
