package lib.kubernetes

default is_gatekeeper = false

is_gatekeeper {
	has_field(input, "review")
	has_field(input.review, "object")
}

object = input {
	not is_gatekeeper
}

object = input.review.object {
	is_gatekeeper
}

format(msg) = gatekeeper_format {
	is_gatekeeper
	gatekeeper_format = {"msg": msg}
}

format(msg) = msg {
	not is_gatekeeper
}

name = object.metadata.name

default namespace = "default"

namespace = object.metadata.namespace

#annotations = object.metadata.annotations

kind = object.kind

apiVersion = object.apiVersion

metadata = object.metadata

is_service {
	kind = "Service"
}

is_controller {
	kind = "CronJob"
}

is_controller {
	kind = "StatefulSet"
}

is_controller {
	kind = "Deployment"
}

is_controller {
	kind = "Daemonset"
}

is_deployment {
	kind = "Deployment"
}

is_pod {
	kind = "Pod"
}

default is_controller = false

is_controller {
	kind = "Deployment"
}

is_controller {
	kind = "StatefulSet"
}

is_controller {
	kind = "DaemonSet"
}

is_controller {
	kind = "ReplicaSet"
}

is_controller {
	kind = "ReplicationController"
}

is_controller {
	kind = "Job"
}

is_cronjob {
	kind = "CronJob"
}

split_image(image) = [image, "latest"] {
	not contains(image, ":")
}

split_image(image) = [image_name, tag] {
	[image_name, tag] = split(image, ":")
}

pod_containers(pod) = all_containers {
	keys = {"containers", "initContainers"}
	all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

containers[container] {
	pods[pod]
	all_containers = pod_containers(pod)
	container = all_containers[_]
}

containers[container] {
	all_containers = pod_containers(object)
	container = all_containers[_]
}

pods[pod] {
	is_deployment
	pod = object.spec.template
}

pods[pod] {
	is_pod
	pod = object
}

pods[pod] {
	is_controller
	pod = object.spec.template
}

pods[pod] {
	is_cronjob
	pod = object.spec.jobTemplate.spec.template
}

volumes[volume] {
	pods[pod]
	volume = pod.spec.volumes[_]
}

dropped_capability(container, cap) {
	container.securityContext.capabilities.drop[_] == cap
}

added_capability(container, cap) {
	container.securityContext.capabilities.add[_] == cap
}

has_field(obj, field) {
	obj[field]
}

no_read_only_filesystem(c) {
	not has_field(c, "securityContext")
}

no_read_only_filesystem(c) {
	has_field(c, "securityContext")
	not has_field(c.securityContext, "readOnlyRootFilesystem")
}

priviledge_escalation_allowed(c) {
	not has_field(c, "securityContext")
}

priviledge_escalation_allowed(c) {
	has_field(c, "securityContext")
	has_field(c.securityContext, "allowPrivilegeEscalation")
}

annotations[annotation] {
	pods[pod]
	annotation = pod.metadata.annotations
}

host_ipcs[host_ipc] {
	pods[pod]
	host_ipc = pod.spec.hostIPC
}

host_networks[host_network] {
	pods[pod]
	host_network = pod.spec.hostNetwork
}

host_pids[host_pid] {
	pods[pod]
	host_pid = pod.spec.hostPID
}

host_aliases[host_alias] {
	pods[pod]
	host_alias = pod.spec
}

# Get all containers and check kubernetes metadata for tiller
tillerDeployed[container] {
	allContainers := containers[_]
	checkMetadata(metadata)
	trace(sprintf("metadata = %v and its present: %V",[metadata, checkMetadata(metadata)]))
	container := allContainers.name
}

# Get all containers and check each image for tiller
tillerDeployed[container] {
	allContainers := containers[_]
	contains(allContainers.image, "tiller")
	trace(sprintf("Image name = %v and its contains tiller: %v",[allContainers.image, contains(allContainers.image, "tiller")]))
	container := allContainers.name
}

# Get all pods and check each metadata for tiller
tillerDeployed[container] {
	allPods := pods[_]
	checkMetadata(allPods.metadata)
	trace(sprintf("Pods metadata is %v and its contains tiller: %V",[allPods.metadata, checkMetadata(allPods.metadata)]))
	container := allPods.metadata.name
}


# Check for tiller in name field 
checkMetadata(metadata) {
	contains(metadata.name, "tiller")
}

# Check for tiller if app is helm
checkMetadata(metadata) {
	has_field(metadata.labels, "app")
	contains(metadata.labels.app, "helm")
}

# Check for tiller in labels.name field
checkMetadata(metadata) {
	has_field(metadata.labels, "name")
	contains(metadata.labels.name, "tiller")
}
