package main
import rego.v1

# HIPAA § 164.312(d) - Person or Entity Authentication
# Verify identity before PHI access

# 1) Missing authentication config
deny contains msg if {
  not input.application.security.authentication
  msg := "HIPAA § 164.312(d): 'authentication' configuration is missing"
}

# 2) MFA not required
deny contains msg if {
  input.application.security.authentication.mfa_required == false
  msg := "HIPAA § 164.312(d): multi-factor authentication must be required for PHI access"
}

# 3) Weak password policy
deny contains msg if {
  policy := input.application.security.authentication.password_policy
  policy.min_length < 8
  msg := sprintf("HIPAA § 164.312(d): password minimum length is %d (must be ≥8)", [policy.min_length])
}

# 4) Missing password complexity
deny contains msg if {
  policy := input.application.security.authentication.password_policy
  not policy.require_special_chars
  msg := "HIPAA § 164.312(d): password policy must require special characters"
}

# 5) Session token too long
deny contains msg if {
  token_ttl := input.application.security.authentication.token_ttl_hours
  token_ttl > 8
  msg := sprintf("HIPAA § 164.312(d): authentication token TTL is %d hours (must be ≤8)", [token_ttl])
}