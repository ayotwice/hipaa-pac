# HIPAA AC-12: Session Timeout Enforcement

This repository implements HIPAA Security Rule AC-12 (Session Termination) using OPA/Rego + Conftest.

## Control Implemented
**AC-12: Session Termination** - Enforce session timeouts ≤ 900 seconds (15 minutes) to prevent unauthorized access from abandoned sessions.

## Quick Start
```bash
# Test the policy
conftest test policy-tests/ac-12-bad-config.yaml --policy policy -o table

# Export artifacts
conftest test policy-tests/ac-12-bad-config.yaml --policy policy -o json > conftest_output.json
conftest test policy-tests/ac-12-bad-config.yaml --policy policy -o sarif > conftest_output.sarif
```

## Structure
```
├── policy/                  # OPA/Rego policies
├── policy-tests/           # Test configurations
├── .github/workflows/      # CI/CD automation
└── artifacts/             # Test results
```

## Real-World Impact
Prevents scenarios like hospital kiosk sessions left open overnight, reducing risk of unauthorized PHI access.