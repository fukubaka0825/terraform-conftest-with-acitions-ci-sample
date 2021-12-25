package main

#####################################
# Tests of Policy as Code Cases
#####################################

test_no_op_resources_are_not_targets {
	plan := `
      resource_changes:
        - name: common case normal
          address: module.one
          type: aws_security_group_rule
          change:
            actions:
              - no-op
            after:
              tags:
                name: normal common case
                owner: hoge
                description: for test
    `

	input := yaml.unmarshal(plan)
	trace(sprintf("%v", [input]))
	deny_tags_contain_minimum_set == set() with input as input
	deny_data_store_data_tag_is_proper == set() with input as input
}

test_tags_contain_minimum_set {
	plan := `
      resource_changes:
        - name: case normal
          address: module.one
          type: aws_security_group_rule
          change:
            actions:
              - create
            after:
              tags:
                name: hoge
                owner: piyo
                description: for test
    `

	input := yaml.unmarshal(plan)
	deny_tags_contain_minimum_set == set() with input as input
}

test_tags_contain_minimum_set_with_extra_tags {
	plan := `
      resource_changes:
        - name: case normal with extra tags
          address: module.one
          type: aws_security_group_rule
          change:
            actions:
              - create
            after:
              tags:
                name: hoge
                owner: piyo
                description: for test
                reason: test
    `

	input := yaml.unmarshal(plan)
	deny_tags_contain_minimum_set == set() with input as input
}

test_tags_contain_minimum_set_without_minimum {
	plan := `
      resource_changes:
        - name: case abnormal without minimum
          address: module.one
          type: aws_security_group_rule
          change:
            actions:
              - create
            after:
              tags:
                name: hoge
                owner: piyo
    `

	input := yaml.unmarshal(plan)
	deny_tags_contain_minimum_set != set() with input as input
}

test_data_store_data_tag_is_proper_with_proper_data_tag {
	plan := `
      resource_changes:
        - name: case normal with proper data tag
          address: module.one
          type: aws_dynamodb_table
          change:
            actions:
              - create
            after:
              tags:
                name: hoge
                owner: piyo
                description: for test
                data: low
    `

	input := yaml.unmarshal(plan)
	deny_data_store_data_tag_is_proper == set() with input as input
}


test_data_store_data_tag_is_proper_without_proper_data_tag {
	plan := `
      resource_changes:
        - name: case abnormal without proper data tag
          address: module.one
          type: aws_dynamodb_table
          change:
            actions:
              - create
            after:
              tags:
                name: hoge
                owner: piyo
                description: for test
                data: highly
    `

	input := yaml.unmarshal(plan)
	deny_data_store_data_tag_is_proper != set() with input as input
}

