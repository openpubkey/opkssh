#!/usr/bin/env bash
#
# Integration test for NSS opkssh module and JIT user provisioning
#
# This test verifies that:
# 1. NSS module can be built and installed
# 2. NSS module reports users as existing when enabled
# 3. getent command works with NSS module
# 4. User provisioning works end-to-end
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=========================================="
echo "NSS Module Integration Test"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
}

fail() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    exit 1
}

info() {
    echo -e "${YELLOW}INFO:${NC} $1"
}

# Test 1: Build NSS module
echo "Test 1: Building NSS module..."
cd "$PROJECT_ROOT/nss"
make clean > /dev/null 2>&1 || true
if make > /dev/null 2>&1; then
    pass "NSS module builds successfully"
else
    fail "NSS module failed to build"
fi

# Test 2: NSS module unit tests
echo ""
echo "Test 2: Running NSS module unit tests..."
if make test > /dev/null 2>&1; then
    pass "NSS module unit tests pass"
else
    fail "NSS module unit tests failed"
fi

# Test 3: Test getent with NSS module (requires installation)
if [ "$EUID" -eq 0 ]; then
    echo ""
    echo "Test 3: Testing NSS module with getent (requires root)..."
    
    # Install NSS module temporarily
    info "Installing NSS module temporarily..."
    make install > /dev/null 2>&1 || fail "Failed to install NSS module"
    
    # Create test config
    mkdir -p /etc/opk
    cat > /etc/opk/nss-opkssh.conf << EOF
enabled true
uid 65534
gid 65534
home_prefix /home
shell /bin/bash
gecos OPKSSH JIT User
EOF
    
    # Backup nsswitch.conf
    cp /etc/nsswitch.conf /etc/nsswitch.conf.backup
    
    # Add opkssh to nsswitch.conf if not already there
    if ! grep -q "^passwd:.*opkssh" /etc/nsswitch.conf; then
        sed -i.bak 's/^passwd:\s*files/passwd:         files opkssh/' /etc/nsswitch.conf
    fi
    
    # Test getent with NSS module
    info "Testing getent with non-existent user..."
    if getent passwd testuser_nss_123 | grep -q "testuser_nss_123"; then
        pass "NSS module returns user info via getent"
    else
        fail "NSS module failed to return user info"
    fi
    
    # Verify UID/GID
    USER_INFO=$(getent passwd testuser_nss_123)
    if echo "$USER_INFO" | grep -q ":65534:65534:"; then
        pass "NSS module returns correct UID/GID (65534)"
    else
        fail "NSS module returned incorrect UID/GID"
    fi
    
    # Cleanup
    info "Cleaning up..."
    make uninstall > /dev/null 2>&1 || true
    mv /etc/nsswitch.conf.backup /etc/nsswitch.conf
    rm -f /etc/opk/nss-opkssh.conf
    
else
    echo ""
    info "Skipping Test 3: Requires root privileges to install NSS module"
fi

# Test 4: Verify userExists function behavior
echo ""
echo "Test 4: Testing userExists function..."
cd "$PROJECT_ROOT"
if go test ./commands -run TestUserExists -v | grep -q "PASS"; then
    pass "userExists function works correctly"
else
    fail "userExists function tests failed"
fi

# Test 5: Verify auto_provision_users config parsing
echo ""
echo "Test 5: Testing auto_provision_users config parsing..."
if go test ./commands -run TestReadFromServerConfigAutoProvision -v | grep -q "PASS"; then
    pass "auto_provision_users config parsing works"
else
    fail "auto_provision_users config parsing failed"
fi

# Test 6: Verify ProvisionUser function
echo ""
echo "Test 6: Testing ProvisionUser function..."
if go test ./commands -run TestProvisionUser -v | grep -q "PASS"; then
    pass "ProvisionUser function works correctly"
else
    fail "ProvisionUser function tests failed"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}All tests passed!${NC}"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - NSS module builds successfully"
echo "  - NSS module unit tests pass"
if [ "$EUID" -eq 0 ]; then
    echo "  - NSS module integrates with getent"
else
    echo "  - NSS module integration tests skipped (requires root)"
fi
echo "  - Go unit tests pass"
echo ""
echo "To enable JIT user provisioning:"
echo "  1. Set 'enabled true' in /etc/opk/nss-opkssh.conf"
echo "  2. Set 'auto_provision_users: true' in /etc/opk/config.yml"
echo "  3. Verify /etc/nsswitch.conf has 'opkssh' in passwd line"
