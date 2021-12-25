package tags_validation

test_tags_contain_proper_keys {
	tags := {"name": "test", "owner": "hoge", "description": "normal test"}
	tags_contain_proper_keys(tags)
}

test_tags_contain_proper_keys_missing_key {
	tags := {"owner": "hoge", "description": "abnormal test"}
	not tags_contain_proper_keys(tags)
}

test_has_proper_data_tag {
	tag_value := "high"
	not not_has_proper_data_tag(tag_value)
}

test_has_proper_data_tag_missing_proper_data_tag {
	tag_value := "highly"
	not_has_proper_data_tag(tag_value)
}

test_is_data_tag_required_target_resource_with_target {
	type_1 := "aws_dynamodb_table"
	is_data_tag_required_target_resource(type_1)
	type_2 := "aws_s3_bucket"
	is_data_tag_required_target_resource(type_2)
}

test_is_data_tag_required_target_resource_with_not_target {
	type := "aws_security_group_rule"
	not is_data_tag_required_target_resource(type)
}
