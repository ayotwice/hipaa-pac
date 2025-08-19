@echo off
echo Testing HIPAA Automatic Logoff Policy...
echo.

echo Testing BAD config (should FAIL):
conftest.exe test policy-tests/hipaa-bad-config.yaml --policy policy -o table
echo.

echo Testing GOOD config (should PASS):
conftest.exe test policy-tests/hipaa-good-config.yaml --policy policy -o table
echo.

echo Exporting artifacts...
conftest.exe test policy-tests/hipaa-bad-config.yaml --policy policy -o json > conftest_output.json
conftest.exe test policy-tests/hipaa-bad-config.yaml --policy policy -o sarif > conftest_output.sarif

echo Done! Check conftest_output.json and conftest_output.sarif
pause