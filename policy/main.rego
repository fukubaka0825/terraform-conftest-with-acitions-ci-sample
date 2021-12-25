package main

import data.tags_validation

#####################################
# Policy as Code Cases Rules
#####################################
deny_tags_contain_minimum_set[msg] {
	# Only target resources that have been changed/added.
	changeset := resources_not_no_op_action[_]

	resources := resources_not_contain_minimum_set(changeset)
	resources != []

	msg := sprintf("Invalid tags (missing minimum required tags: name,owner,description) for the following resources: %v", [resources])
}

deny_data_store_data_tag_is_proper[msg] {
	# Only target resources that have been changed/added.
	changeset := resources_not_no_op_action[_]

	# Only when resource_type is a data source/store type that can contain sensitive information
	is_seviarity_tag_required_target_resource(changeset.type)

	tags_validation.not_has_proper_data_tag(changeset.change.after.tags.data)

	msg = sprintf("`%v` data tag needs to be set to one of [low,high,middle]", [module_address[i]])
}

#####################################
# Utils
#####################################

resources_not_no_op_action = {resource | resource := input.resource_changes[_]; resource.change.actions[_] != "no-op"}

resources_with_type(resources, type) = all {
	all := [item | item := resources[_]; item.type == type]
}

module_address[i] = address {
	changeset := input.resource_changes[i]
	address := changeset.address
}

resources_not_contain_minimum_set(changeset) = resources {
	resources := [resource | resource := module_address[i]; not tags_validation.tags_contain_proper_keys(changeset.change.after.tags)]
}

is_seviarity_tag_required_target_resource(type) {
	type == "aws_dynamodb_table"
}

is_seviarity_tag_required_target_resource(type) {
	type == "aws_s3_bucket"
}
