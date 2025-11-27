# Quick Pre-Release Test Script
# Run this to test critical functionality before release

Write-Host "=== CyberSec Scanner Pre-Release Tests ===" -ForegroundColor Cyan
Write-Host ""

$ErrorCount = 0

# Test 1: Build package
Write-Host "[1/10] Building package..." -ForegroundColor Yellow
Remove-Item -Recurse -Force dist, build, *.egg-info -ErrorAction SilentlyContinue
python -m build 2>&1 | Out-Null
if (Test-Path "dist/cybersec_scanner-0.1.0-py3-none-any.whl") {
    Write-Host "  ✓ Package built successfully" -ForegroundColor Green
} else {
    Write-Host "  ✗ Package build failed" -ForegroundColor Red
    $ErrorCount++
}

# Test 2: Validate package
Write-Host "[2/10] Validating package quality..." -ForegroundColor Yellow
$validation = python -m twine check dist/* 2>&1
if ($validation -match "PASSED") {
    Write-Host "  ✓ Package validation passed" -ForegroundColor Green
} else {
    Write-Host "  ✗ Package validation failed" -ForegroundColor Red
    Write-Host "  $validation" -ForegroundColor Red
    $ErrorCount++
}

# Test 3: Create test environment
Write-Host "[3/10] Creating test environment..." -ForegroundColor Yellow
Remove-Item -Recurse -Force test_release_env -ErrorAction SilentlyContinue
python -m venv test_release_env
.\test_release_env\Scripts\activate
if ($?) {
    Write-Host "  ✓ Test environment created" -ForegroundColor Green
} else {
    Write-Host "  ✗ Failed to create environment" -ForegroundColor Red
    $ErrorCount++
}

# Test 4: Install from wheel
Write-Host "[4/10] Installing from wheel..." -ForegroundColor Yellow
pip install dist/cybersec_scanner-0.1.0-py3-none-any.whl --quiet
if ($?) {
    Write-Host "  ✓ Wheel installation successful" -ForegroundColor Green
} else {
    Write-Host "  ✗ Wheel installation failed" -ForegroundColor Red
    $ErrorCount++
}

# Test 5: Test CLI version
Write-Host "[5/10] Testing CLI version command..." -ForegroundColor Yellow
$version = cybersec-scanner --version 2>&1
if ($version -match "0.1.0") {
    Write-Host "  ✓ CLI version correct: $version" -ForegroundColor Green
} else {
    Write-Host "  ✗ CLI version incorrect: $version" -ForegroundColor Red
    $ErrorCount++
}

# Test 6: Test CLI help
Write-Host "[6/10] Testing CLI help command..." -ForegroundColor Yellow
$help = cybersec-scanner --help 2>&1
if ($help -match "scan-git" -and $help -match "scan-web") {
    Write-Host "  ✓ CLI help shows all commands" -ForegroundColor Green
} else {
    Write-Host "  ✗ CLI help incomplete" -ForegroundColor Red
    $ErrorCount++
}

# Test 7: Test SDK imports
Write-Host "[7/10] Testing SDK imports..." -ForegroundColor Yellow
$import_test = python -c 'from cybersec_scanner import scan_git, scan_web, scan_all; print(\"OK\")' 2>&1
if ($import_test -match "OK") {
    Write-Host "  ✓ SDK imports successful" -ForegroundColor Green
} else {
    Write-Host "  ✗ SDK import failed: $import_test" -ForegroundColor Red
    $ErrorCount++
}

# Test 8: Test module imports
Write-Host "[8/10] Testing module imports..." -ForegroundColor Yellow
$module_test = python -c 'from cybersec_scanner.scanners import GitScanner; from cybersec_scanner.rag import KnowledgeGraph; from cybersec_scanner.database import Database; print(\"OK\")' 2>&1
if ($module_test -match "OK") {
    Write-Host "  ✓ Module imports successful" -ForegroundColor Green
} else {
    Write-Host "  ✗ Module import failed: $module_test" -ForegroundColor Red
    $ErrorCount++
}

# Test 9: Test init-config
Write-Host "[9/10] Testing init-config command..." -ForegroundColor Yellow
Remove-Item cybersec-config.yaml -ErrorAction SilentlyContinue
cybersec-scanner init-config --output test-config-output.yaml 2>&1 | Out-Null
if (Test-Path "test-config-output.yaml") {
    Write-Host "  ✓ Config file created successfully" -ForegroundColor Green
    Remove-Item test-config-output.yaml
} else {
    Write-Host "  ✗ Config file creation failed" -ForegroundColor Red
    $ErrorCount++
}

# Test 10: Test python -m entry point
Write-Host "[10/10] Testing python -m entry point..." -ForegroundColor Yellow
$module_entry = python -m cybersec_scanner --version 2>&1
if ($module_entry -match "0.1.0") {
    Write-Host "  ✓ Module entry point works" -ForegroundColor Green
} else {
    Write-Host "  ✗ Module entry point failed: $module_entry" -ForegroundColor Red
    $ErrorCount++
}

# Cleanup
Write-Host ""
Write-Host "Cleaning up test environment..." -ForegroundColor Yellow
deactivate
Remove-Item -Recurse -Force test_release_env -ErrorAction SilentlyContinue

# Summary
Write-Host ""
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
if ($ErrorCount -eq 0) {
    Write-Host "ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Ready to release!" -ForegroundColor Green
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Test on TestPyPI: python -m twine upload --repository testpypi dist/*"
    Write-Host "  2. Create GitHub Release: git tag v0.1.0; git push origin v0.1.0"
    Write-Host "  3. Upload to PyPI: python -m twine upload dist/*"
    exit 0
} else {
    Write-Host ("FAILED: " + $ErrorCount + " test(s) failed") -ForegroundColor Red
    Write-Host ""
    Write-Host "Please fix the issues before releasing." -ForegroundColor Red
    exit 1
}
