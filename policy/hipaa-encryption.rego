package main
import rego.v1

# HIPAA § 164.312(a)(2)(ii) - Encryption and Decryption
# Require encryption for PHI at rest and in transit

# 1) Missing encryption config
deny contains msg if {
  not input.application.security.encryption
  msg := "HIPAA § 164.312(a)(2)(ii): 'encryption' configuration is missing"
}

# 2) Encryption disabled
deny contains msg if {
  input.application.security.encryption.enabled == false
  msg := "HIPAA § 164.312(a)(2)(ii): encryption must be enabled for PHI protection"
}

# 3) Weak encryption algorithm
deny contains msg if {
  algo := input.application.security.encryption.algorithm
  not algo in ["AES-256", "AES-256-GCM", "ChaCha20-Poly1305"]
  msg := sprintf("HIPAA § 164.312(a)(2)(ii): encryption algorithm '%s' is not approved (use AES-256, AES-256-GCM, or ChaCha20-Poly1305)", [algo])
}

# 4) Missing at-rest encryption
deny contains msg if {
  not input.application.security.encryption.at_rest
  msg := "HIPAA § 164.312(a)(2)(ii): at-rest encryption must be configured"
}

# 5) Missing in-transit encryption
deny contains msg if {
  not input.application.security.encryption.in_transit
  msg := "HIPAA § 164.312(a)(2)(ii): in-transit encryption must be configured"
}