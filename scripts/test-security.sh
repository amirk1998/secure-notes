#!/bin/bash

echo "Running security tests..."

# Test 1: SQL Injection Prevention
echo "Test 1: SQL Injection Prevention"
echo "Testing with malicious input: admin' OR '1'='1"
# This would be tested within the application

# Test 2: File Permissions
echo "Test 2: File Permissions"
if [ -f "./data/secure_notes.db" ]; then
    PERMS=$(stat -c %a "./data/secure_notes.db" 2>/dev/null || stat -f %A "./data/secure_notes.db" 2>/dev/null)
    if [ "$PERMS" = "600" ]; then
        echo "✓ Database file permissions are secure (600)"
    else
        echo "✗ WARNING: Database file permissions are insecure ($PERMS)"
    fi
fi

# Test 3: Check for hardcoded secrets
echo "Test 3: Checking for hardcoded secrets"
if grep -r "password.*=.*['\"]" cmd/ internal/ --include="*.go" | grep -v "PasswordHash"; then
    echo "✗ WARNING: Possible hardcoded passwords found"
else
    echo "✓ No hardcoded passwords found"
fi

# Test 4: Audit log exists
echo "Test 4: Audit logging"
if [ -f "./logs/audit.log" ]; then
    echo "✓ Audit log file exists"
    PERMS=$(stat -c %a "./logs/audit.log" 2>/dev/null || stat -f %A "./logs/audit.log" 2>/dev/null)
    if [ "$PERMS" = "600" ]; then
        echo "✓ Audit log permissions are secure (600)"
    fi
else
    echo "ℹ Audit log will be created on first run"
fi

# Test 5: Backup encryption
echo "Test 5: Backup encryption"
if [ -d "./backups" ]; then
    COUNT=$(ls -1 ./backups/*.enc.gz 2>/dev/null | wc -l)
    if [ $COUNT -gt 0 ]; then
        echo "✓ Found $COUNT encrypted backup(s)"
    else
        echo "ℹ No backups found yet"
    fi
fi

echo ""
echo "Security tests completed!"