output "bucket_name" {
  description = "Primary bucket name."
  value       = aws_s3_bucket.primary.id
}

output "bucket_arn" {
  description = "Primary bucket ARN."
  value       = aws_s3_bucket.primary.arn
}

output "log_bucket_name" {
  description = "Log bucket name."
  value       = aws_s3_bucket.log.id
}

# TODO (SC-28 attestation): once you add the encryption configuration, add an
# output that surfaces the algorithm in effect (for example "AES256"). This is
# your machine-readable proof of encryption at rest.

output "encrypt_config_primary_value" {
  description = "Encryption configuration for primary bucket"
  value       = one(aws_s3_bucket_server_side_encryption_configuration.encrypt_config_primary.rule).apply_server_side_encryption_by_default[0].sse_algorithm
}

output "encrypt_config_log_value" {
  description = "Encryption configuration for log bucket"
  value       = one(aws_s3_bucket_server_side_encryption_configuration.encrypt_config_log.rule).apply_server_side_encryption_by_default[0].sse_algorithm
}