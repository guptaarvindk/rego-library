package global.libraries["crossplane-k8s"]
# Copyright 2023 Styra Inc. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

import data.library.parameters
import future.keywords.in

#############################################################################
# METADATA: library-snippet/kubernetes
# version: v1
# title: "CROSSPLANE: Restrict S3 bucket to be only deployed in given region"
# description: >-
#   This custom snippet Restrict S3 bucket to be only deployed in given region.
# filePath:
# - systems/.*/policy/com.styra.kubernetes.validating/rules/.*
# - stacks/.*/policy/com.styra.kubernetes.validating/rules/.*
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[message]"
# schema:
#   parameters:
#     - name: allowed_regions
#       type: set_of_strings
#       placeholder: "Examples: us-west-1, us-west-2"
#       required: true
#   decision:
#     - type: rego
#       key: allowed
#       value: "false"
#     - type: rego
#       key: message
#       value: "message"
#############################################################################
restrict_s3_region[message] {
	action_is_s3_bucket_create(parameters.allowed_regions)
	not is_valid_region_for_bucket(parameters.allowed_regions)

	message := sprintf("Bucket region %s is not in allowed list", [input.request.object.spec.forProvider.region])
}

action_is_s3_bucket_create(allowed_regions) {
	input.request.kind.group == "s3.aws.upbound.io"
	input.request.kind.kind == "Bucket"
	input.request.operation == "CREATE"
}

is_valid_region_for_bucket(allowed_regions) {
	input.request.object.spec.forProvider.region in allowed_regions
}

