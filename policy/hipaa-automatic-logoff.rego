package main
import rego.v1

# HIPAA § 164.312(a)(2)(i) - Automatic Logoff
# Enforce session timeouts ≤ 900 seconds (15 minutes) for PHI access

# 1) Missing session_timeout entirely
deny contains msg if {
  not input.application.settings.session_timeout
  msg := "HIPAA § 164.312(a)(2)(i): 'session_timeout' is missing from application settings"
}

# 2) Empty session_timeout
deny contains msg if {
  input.application.settings.session_timeout == ""
  msg := "HIPAA § 164.312(a)(2)(i): 'session_timeout' is defined but empty"
}

# 3) Explicitly set to 'never' (prohibited)
deny contains msg if {
  input.application.settings.session_timeout == "never"
  msg := "HIPAA § 164.312(a)(2)(i): 'session_timeout' must not be 'never' - automatic logoff required"
}

# 4a) Numeric timeout exceeds 900 seconds
deny contains msg if {
  type_name(input.application.settings.session_timeout) == "number"
  input.application.settings.session_timeout > 900
  msg := sprintf(
    "HIPAA § 164.312(a)(2)(i): 'session_timeout' is %d seconds (exceeds 900 second limit)",
    [input.application.settings.session_timeout],
  )
}

# 4b) String numeric timeout exceeds 900 seconds
deny contains msg if {
  val := input.application.settings.session_timeout
  type_name(val) == "string"
  regex.match("^[0-9]+$", val)
  to_number(val) > 900
  msg := sprintf(
    "HIPAA § 164.312(a)(2)(i): 'session_timeout' is %d seconds (exceeds 900 second limit)",
    [to_number(val)],
  )
}