# METADATA
# title: AC-3 - Access Enforcement (AWS S3 public access block)
# description: Every aws_s3_bucket must have a public access block with all four flags true.
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
#   remediation: Add aws_s3_bucket_public_access_block referencing the bucket, all four flags true.
package compliance.ac3_aws

import rego.v1

# TODO (your build): deny any aws_s3_bucket that does not have a matching
# aws_s3_bucket_public_access_block with block_public_acls, block_public_policy,
# ignore_public_acls, and restrict_public_buckets all set to true.
#
# Match the bucket by reference the way sc28_encryption_aws.rego does, in
# input.configuration.root_module.resources[].expressions.bucket.references.
# Read the four flag values from input.planned_values.root_module.resources[]
# where .address is the public access block's address.
#
# The stub below keeps `deny` defined (empty) so the test file loads. Replace it.
deny contains msg if {
	bucket := input.configuration.root_module.resources[_]
	bucket.type == "aws_s3_bucket"
	not bucket_has_access_block(bucket)
	msg := sprintf("aws_s3_bucket %s has no access enforcement for public access", [bucket.name])
}

bucket_has_access_block(bucket) if {
	access_block := input.configuration.root_module.resources[_]
	access_block.type == "aws_s3_bucket_public_access_block"
	ac_plan_reference := input.planned_values.root_module.resources[_]
	ac_plan_reference.address == sprintf("aws_s3_bucket_public_access_block.%s", [access_block.name])
	ac_plan_reference.values.block_public_acls == true
	ac_plan_reference.values.block_public_policy == true
	ac_plan_reference.values.ignore_public_acls == true
	ac_plan_reference.values.restrict_public_buckets == true
	ac_bucket_reference := access_block.expressions.bucket.references[_]
	ac_bucket_reference == sprintf("aws_s3_bucket.%s.id", [bucket.name])
}