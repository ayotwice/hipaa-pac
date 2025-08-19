package main
import rego.v1

# HIPAA § 164.312(b) - Audit Controls
# Record and examine PHI access and activity

# 1) Missing audit config
deny contains msg if {
  not input.application.security.audit
  msg := "HIPAA § 164.312(b): 'audit' configuration is missing"
}

# 2) Audit logging disabled
deny contains msg if {
  input.application.security.audit.enabled == false
  msg := "HIPAA § 164.312(b): audit logging must be enabled for PHI access tracking"
}

# 3) Insufficient log retention
deny contains msg if {
  retention := input.application.security.audit.retention_days
  retention < 2555  # 7 years in days
  msg := sprintf("HIPAA § 164.312(b): audit log retention is %d days (must be ≥2555 days/7 years)", [retention])
}

# 4) Missing required events
deny contains msg if {
  events := input.application.security.audit.logged_events
  required := ["login", "logout", "phi_access", "phi_modification", "failed_auth"]
  missing := [r | r := required[_]; not r in events]
  count(missing) > 0
  msg := sprintf("HIPAA § 164.312(b): missing required audit events: %v", [missing])
}

# 5) Audit logs not protected
deny contains msg if {
  input.application.security.audit.tamper_protection == false
  msg := "HIPAA § 164.312(b): audit logs must have tamper protection enabled"
}