package appshield.kubernetes.KSV102

import data.lib.kubernetes
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV102",
	"title": "Tiller (Helm v2) Is Deployed",
	"version": "v1.0.0",
	"severity": "Critical",
	"type": "Kubernetes Security Check",
	"description": "Check if Tiller is deployed.",
	"recommended_actions": "TBD",
}

# Get all containers and check kubernetes metadata for tiller
tillerDeployed[container] {
	allContainers := kubernetes.containers[_]
	checkMetadata(kubernetes.metadata)
	container := allContainers.name
}

# Get all containers and check each image for tiller
tillerDeployed[container] {
	allContainers := kubernetes.containers[_]
	contains(allContainers.image, "tiller")
	container := allContainers.name
}

# Get all pods and check each metadata for tiller
tillerDeployed[container] {
	allPods := kubernetes.pods[_]
	checkMetadata(allPods.metadata)
	container := allPods.name
}

getNoTiller[container] {
	container := kubernetes.containers[_].name
	not tillerDeployed[container]
}

# checkRequiredDropCapabilities is true if requiredDropCapabilities does include 'ALL' or 'NET_RAW'
# or if requiredDropCapabilities drop is not specified at all.
CheckNoTiller {
	count(getNoTiller) > 0
}

deny[res] {
	CheckNoTiller

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should have tiller deployed", [getNoTiller[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

# Check for tiller in name field 
checkMetadata(metadata) {
	contains(metadata.name, "tiller")
}

# Check for tiller if app is helm
checkMetadata(metadata) {
	object.get(metadata.labels, "app", "undefined") == "helm"
}

# Check for tiller in labels.name field
checkMetadata(metadata) {
	contains(object.get(metadata.labels, "name", "undefined"), "tiller")
}
