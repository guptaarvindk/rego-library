package global.libraries.kubernetes

# Copyright 2023 Styra Inc. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

import data.library.parameters
import future.keywords.in

#############################################################################
# METADATA: library-snippet/kubernetes
# version: v1
# title: "CUSTOM: Prohibit deletion of protected deployments except by admins"
# description: >-
#   This custom snippet prevents the deletion of protected deployments unless its by a specified admin.
# filePath:
# - systems/.*/policy/com.styra.kubernetes.validating/rules/.*
# - stacks/.*/policy/com.styra.kubernetes.validating/rules/.*
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[message]"
# schema:
#   parameters:
#     - name: allowed_users
#       type: set_of_strings
#       placeholder: "Examples: admin@example.com, admin-user"
#       required: true
#     - name: protected_deployments
#       type: set_of_strings
#       placeholder: "Examples: k8sctl, k8state"
#       required: true
#   decision:
#     - type: rego
#       key: allowed
#       value: "false"
#     - type: rego
#       key: message
#       value: "message"
#############################################################################
prohibit_delete_deployment[message] {
	action_is_delete_deployment(parameters.protected_deployments)
	not is_allowed_to_delete_resource(parameters.allowed_users)

	message := sprintf("User %s is not authorized to delete protected deployment %s", [input.request.name, input.request.userInfo.username])
}

action_is_delete_deployment(protected_deployments) {
	input.request.kind.kind == "Deployment"
	input.request.operation == "DELETE"
	input.request.name in protected_deployments
}

is_allowed_to_delete_resource(allowed_users) {
	input.request.userInfo.username in allowed_users
}



#############################################################################
# METADATA: library-snippet/kubernetes
# version: v1
# title: "Podz: Prohibit Specified Host Paths"
# description: >-
#   Prevent volumes from accessing prohibited paths on the host node’s file system.
# filePath:
# - systems/.*/policy/com.styra.kubernetes.validating/rules/.*
# - stacks/.*/policy/com.styra.kubernetes.validating/rules/.*
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[message]"
# schema:
#   parameters:
#     - name: prohibited_host_paths
#       type: set_of_strings
#       placeholder: "Examples: /var/run/docker.sock, /var/run/xxx"
#       required: true
#   decision:
#     - type: rego
#       key: allowed
#       value: "false"
#     - type: rego
#       key: message
#       value: "message"
#############################################################################

deny_host_path_in_blacklist[message] {
	count(parameters.prohibited_host_paths) > 0
	volume := input.request.object.spec.volumes[_]
	item := parameters.prohibited_host_paths[_]
	glob.match(item, [], volume.hostPath.path)
	message := sprintf("Resource %v uses a prohibited host path.", [utils.input_id])
}



