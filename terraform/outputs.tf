output "hipaa_user_name" {
  description = "Name of the created HIPAA-compliant user"
  value       = aws_iam_user.hipaa_user.name
}

output "hipaa_user_arn" {
  description = "ARN of the created HIPAA-compliant user"
  value       = aws_iam_user.hipaa_user.arn
}