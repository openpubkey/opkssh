#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

setUp() {
    mock_command_found=true
    mock_getenforce="Enforcing"
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    mkdir "$TEST_TEMP_DIR/tmp"
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    touch "$MOCK_LOG"
    HOME_POLICY=true
    SELINUX_ENABLE_SQUID=false
    SELINUX_ENABLE_PROXY=false
    export HOME_POLICY SELINUX_ENABLE_SQUID SELINUX_ENABLE_PROXY

    DUMMY_TE_CONTENT="module dummy 1.0; require { type sshd_t; }; allow sshd_t self:process { transition };"
}

tearDown() {
    /usr/bin/rm -rf "$TEST_TEMP_DIR"
}


# Mocking commands
command() {
    if [[ "$1" == "-v" && "$2" == "getenforce" ]]; then
        $mock_command_found && return 0 || return 1
    fi
    builtin command "$@"
}

wget() {
    echo "wget $*" >> "$MOCK_LOG"
    if [[ "$1" == "-q" ]]; then
        echo "$DUMMY_TE_CONTENT" > "$3"
        echo "$DUMMY_TE_CONTENT" > "${TEST_TEMP_DIR}${3}"
    fi
}

getenforce() {
    echo "getenforce $*" >> "$MOCK_LOG"
    echo "$mock_getenforce"
}

checkmodule() {
    echo "checkmodule $*" >> "$MOCK_LOG"
    /usr/bin/cat "$TE_TMP" >> "$MOCK_LOG"
}

restorecon() {
    echo "restorecon $*" >> "$MOCK_LOG"
}

semodule_package() {
    echo "semodule_package $*" >> "$MOCK_LOG"
}

semodule() {
    echo "semodule $*" >> "$MOCK_LOG"
}

setsebool() {
    echo "setsebool $*" >> "$MOCK_LOG"
}

rm() {
    echo "rm $*" >> "$MOCK_LOG"
    /usr/bin/rm "$@"
}


# Running tests

test_check_selinux_no_getenforce() {
    mock_command_found=false
    output=$(check_selinux 2>&1)
    result=$?

    assertEquals "Expected to return 0 when getenforce isn't found" 0 "$result"
    assertEquals "Expected output to echo when getenforce isn't fount" "SELinux is disabled" "$output"
}

test_check_selinux_disabled() {
    mock_getenforce="Disabled"
    output=$(check_selinux 2>&1)
    result=$?

    assertEquals "Expected to return 0 when SELinux is disabled" 0 "$result"
    assertEquals "Expected output to be empty when SELinux is disabled" "" "$output"

}

test_check_selinux_home_policy() {
    output=$(check_selinux 2>&1)
    result=$?
    mock_log=$(cat "$MOCK_LOG")
    te_path="${TEST_TEMP_DIR}/tmp/opkssh.te"

    # Check that dummy content was written
    actual_te_content=$(cat "$te_path" 2>/dev/null)
    assertEquals "Expected downloaded TE file to contain dummy content" "$DUMMY_TE_CONTENT" "$actual_te_content"

    assertEquals "Expected return code 0" 0 "$result"
    assertContains "Expected restorecon called" "$mock_log" "restorecon ${INSTALL_DIR}/${BINARY_NAME}"
    assertContains "Expected checkmodule called" "$mock_log" "checkmodule -M -m -o /tmp/opkssh.mod /tmp/opkssh.te"
    assertContains "Expected semodule_package called" "$mock_log" "semodule_package -o /tmp/opkssh.pp -m /tmp/opkssh.mod"
    assertContains "Expected semodule called" "$mock_log" "semodule -i /tmp/opkssh.pp"
    assertContains "Expected opkssh_enable_home set" "$mock_log" "setsebool -P opkssh_enable_home on"
    assertNotContains "Expected opkssh_enable_squid set" "$mock_log" "setsebool -P opkssh_enable_squid on"
    assertNotContains "Expected opkssh_enable_proxy set" "$mock_log" "setsebool -P opkssh_enable_proxy on"
    assertContains "Expected rm called" "$mock_log" "rm -f /tmp/opkssh.te /tmp/opkssh.mod /tmp/opkssh.pp"
}

test_check_selinux_no_home_policy() {
    HOME_POLICY=false
    output=$(check_selinux 2>&1)
    result=$?
    mock_log=$(cat "$MOCK_LOG")
    te_path="${TEST_TEMP_DIR}/tmp/opkssh.te"

    actual_te_content=$(cat "$te_path" 2>/dev/null)
    assertEquals "Expected downloaded TE file to contain dummy content" "$DUMMY_TE_CONTENT" "$actual_te_content"

    assertEquals "Expected return code 0" 0 "$result"
    assertContains "Expected restorecon called" "$mock_log" "restorecon ${INSTALL_DIR}/${BINARY_NAME}"
    assertContains "Expected checkmodule called" "$mock_log" "checkmodule -M -m -o /tmp/opkssh.mod /tmp/opkssh.te"
    assertContains "Expected semodule_package called" "$mock_log" "semodule_package -o /tmp/opkssh.pp -m /tmp/opkssh.mod"
    assertContains "Expected semodule called" "$mock_log" "semodule -i /tmp/opkssh.pp"
    assertNotContains "Expected opkssh_enable_home set" "$mock_log" "setsebool -P opkssh_enable_home on"
    assertNotContains "Expected opkssh_enable_squid set" "$mock_log" "setsebool -P opkssh_enable_squid on"
    assertNotContains "Expected opkssh_enable_proxy set" "$mock_log" "setsebool -P opkssh_enable_proxy on"
    assertContains "Expected rm called" "$mock_log" "rm -f /tmp/opkssh.te /tmp/opkssh.mod /tmp/opkssh.pp"
}


test_check_selinux_enable_squid() {
    SELINUX_ENABLE_SQUID=true
    output=$(check_selinux 2>&1)
    result=$?
    mock_log=$(cat "$MOCK_LOG")
    te_path="${TEST_TEMP_DIR}/tmp/opkssh.te"

    # Check that dummy content was written
    actual_te_content=$(cat "$te_path" 2>/dev/null)
    assertEquals "Expected downloaded TE file to contain dummy content" "$DUMMY_TE_CONTENT" "$actual_te_content"

    assertEquals "Expected return code 0" 0 "$result"
    assertContains "Expected restorecon called" "$mock_log" "restorecon ${INSTALL_DIR}/${BINARY_NAME}"
    assertContains "Expected checkmodule called" "$mock_log" "checkmodule -M -m -o /tmp/opkssh.mod /tmp/opkssh.te"
    assertContains "Expected semodule_package called" "$mock_log" "semodule_package -o /tmp/opkssh.pp -m /tmp/opkssh.mod"
    assertContains "Expected semodule called" "$mock_log" "semodule -i /tmp/opkssh.pp"
    assertContains "Expected opkssh_enable_home set" "$mock_log" "setsebool -P opkssh_enable_home on"
    assertContains "Expected opkssh_enable_squid set" "$mock_log" "setsebool -P opkssh_enable_squid on"
    assertNotContains "Expected opkssh_enable_proxy set" "$mock_log" "setsebool -P opkssh_enable_proxy on"
    assertContains "Expected rm called" "$mock_log" "rm -f /tmp/opkssh.te /tmp/opkssh.mod /tmp/opkssh.pp"
}

test_check_selinux_enable_proxy() {
    SELINUX_ENABLE_PROXY=true
    output=$(check_selinux 2>&1)
    result=$?
    mock_log=$(cat "$MOCK_LOG")
    te_path="${TEST_TEMP_DIR}/tmp/opkssh.te"

    # Check that dummy content was written
    actual_te_content=$(cat "$te_path" 2>/dev/null)
    assertEquals "Expected downloaded TE file to contain dummy content" "$DUMMY_TE_CONTENT" "$actual_te_content"

    assertEquals "Expected return code 0" 0 "$result"
    assertContains "Expected restorecon called" "$mock_log" "restorecon ${INSTALL_DIR}/${BINARY_NAME}"
    assertContains "Expected checkmodule called" "$mock_log" "checkmodule -M -m -o /tmp/opkssh.mod /tmp/opkssh.te"
    assertContains "Expected semodule_package called" "$mock_log" "semodule_package -o /tmp/opkssh.pp -m /tmp/opkssh.mod"
    assertContains "Expected semodule called" "$mock_log" "semodule -i /tmp/opkssh.pp"
    assertContains "Expected opkssh_enable_home set" "$mock_log" "setsebool -P opkssh_enable_home on"
    assertNotContains "Expected opkssh_enable_squid set" "$mock_log" "setsebool -P opkssh_enable_squid on"
    assertContains "Expected opkssh_enable_proxy set" "$mock_log" "setsebool -P opkssh_enable_proxy on"
    assertContains "Expected rm called" "$mock_log" "rm -f /tmp/opkssh.te /tmp/opkssh.mod /tmp/opkssh.pp"
}

# shellcheck disable=SC1091
source shunit2
