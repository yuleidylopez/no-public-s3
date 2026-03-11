package s3policy

deny[message] {
  input.resource_type == "aws_s3_bucket"
  input.acl == "private"
  message := "S3 buckets cannot be publicly readable (acl: public-read)"
}
