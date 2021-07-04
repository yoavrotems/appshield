package appshield.kubernetes.KSV103

import data.lib.kubernetes

__rego_metadata__ := {
	"id": "KSV102",
	"title": "Tiller (Helm v2) Is Deployed",
	"version": "v1.0.0",
	"severity": "Critical",
	"type": "Kubernetes Security Check",
	"description": "Check if Tiller is deployed.",
	"recommended_actions": "TBD",
}

isTiller[container] {
	container := kubernetes.tillerDeployed[_]
}

deny[res] {
	tillerDeployedContainers = isTiller
	count(tillerDeployedContainers) > 0

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace shouldn't have tiller deployed", [isTiller[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
