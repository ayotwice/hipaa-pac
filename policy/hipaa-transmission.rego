package main
import rego.v1

# HIPAA § 164.312(e)(2)(ii) - Encryption for Transmission
# Secure PHI during network transmission

# 1) Missing transmission config
deny contains msg if {
  not input.application.security.transmission
  msg := "HIPAA § 164.312(e)(2)(ii): 'transmission' security configuration is missing"
}

# 2) TLS not enforced
deny contains msg if {
  input.application.security.transmission.enforce_tls == false
  msg := "HIPAA § 164.312(e)(2)(ii): TLS must be enforced for PHI transmission"
}

# 3) Weak TLS version
deny contains msg if {
  version := input.application.security.transmission.min_tls_version
  not version in ["1.2", "1.3"]
  msg := sprintf("HIPAA § 164.312(e)(2)(ii): TLS version '%s' is not secure (use 1.2 or 1.3)", [version])
}

# 4) HTTP allowed
deny contains msg if {
  input.application.security.transmission.allow_http == true
  msg := "HIPAA § 164.312(e)(2)(ii): HTTP must not be allowed for PHI transmission"
}

# 5) Weak cipher suites
deny contains msg if {
  ciphers := input.application.security.transmission.cipher_suites
  weak_cipher := ciphers[_]
  contains(weak_cipher, "RC4")
  msg := sprintf("HIPAA § 164.312(e)(2)(ii): cipher suite '%s' contains weak RC4", [weak_cipher])
}