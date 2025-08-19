variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "user_id" {
  description = "Unique identifier for the user"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.user_id))
    error_message = "User ID must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}