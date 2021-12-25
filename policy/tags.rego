package tags_validation

minimum_tags = {"name", "owner", "description"}

tags_contain_proper_keys(tags) {
	# Subtract the key list of the given tags from the minimum tag list, and if there is no more left, you have the minimum tag.
	keys := {key | tags[key]}
	leftover := minimum_tags - keys
	leftover == set()
}

not_has_proper_data_tag(value) {
	value != "low"
	value != "middle"
	value != "high"
}
