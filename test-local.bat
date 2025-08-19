@echo off
echo Testing HIPAA Compliance Suite...
echo.

echo === Testing BAD Configs (should FAIL) ===
echo 1. Automatic Logoff:
conftest.exe test policy-tests/hipaa-bad-config.yaml --policy policy -o table
echo.

echo 2. Encryption:
conftest.exe test policy-tests/hipaa-encryption-bad.yaml --policy policy -o table
echo.

echo 3. Authentication:
conftest.exe test policy-tests/hipaa-auth-bad.yaml --policy policy -o table
echo.

echo 4. Transmission Security:
conftest.exe test policy-tests/hipaa-transmission-bad.yaml --policy policy -o table
echo.

echo 5. Audit Controls:
conftest.exe test policy-tests/hipaa-audit-bad.yaml --policy policy -o table
echo.

echo === Testing GOOD Configs (should PASS) ===
echo 1. Automatic Logoff:
conftest.exe test policy-tests/hipaa-good-config.yaml --policy policy -o table
echo.

echo 2. Encryption:
conftest.exe test policy-tests/hipaa-encryption-good.yaml --policy policy -o table
echo.

echo 3. Authentication:
conftest.exe test policy-tests/hipaa-auth-good.yaml --policy policy -o table
echo.

echo 4. Transmission Security:
conftest.exe test policy-tests/hipaa-transmission-good.yaml --policy policy -o table
echo.

echo 5. Audit Controls:
conftest.exe test policy-tests/hipaa-audit-good.yaml --policy policy -o table
echo.

echo Exporting artifacts...
conftest.exe test policy-tests/hipaa-*-bad.yaml --policy policy -o json > conftest_output.json
conftest.exe test policy-tests/hipaa-*-bad.yaml --policy policy -o sarif > conftest_output.sarif

echo Done! Check conftest_output.json and conftest_output.sarif
pause