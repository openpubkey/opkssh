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
    LOCAL_TE_FILE=""

    # Default: legacy policy, no sshd_session_t type.
    mock_session_domain_unsupported=true
    mock_checkmodule_fail=false
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
    # Last argument is the TE file being compiled.
    local te_file="${!#}"
    LAST_TE_FILE_CONTENT=$(cat "$te_file" 2>/dev/null)
    echo "$LAST_TE_FILE_CONTENT" >> "$MOCK_LOG"
    $mock_checkmodule_fail && return 1
    return 0
}

restorecon() {
    echo "restorecon $*" >> "$MOCK_LOG"
}

semodule_package() {
    echo "semodule_package $*" >> "$MOCK_LOG"
}

semodule() {
    echo "semodule $*" >> "$MOCK_LOG"
    # Simulate a load-time failure when the module requires a type the
    # target's loaded policy does not define.
    if [[ "$mock_session_domain_unsupported" == true && "$LAST_TE_FILE_CONTENT" == *"sshd_session_t"* ]]; then
        return 1
    fi
    return 0
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

test_check_selinux_local_te_file_uses_session_domain_when_supported() {
    # A policy with sshd_session_t, such as RHEL and CentOS 10.
    mock_session_domain_unsupported=false
    LOCAL_TE_FILE="$TEST_TEMP_DIR/local.te"
    echo "module opkssh 2.0; require { type sshd_t; }; allow sshd_t self:process { transition }; # local" > "$LOCAL_TE_FILE"

    output=$(check_selinux 2>&1)
    result=$?
    mock_log=$(cat "$MOCK_LOG")

    assertEquals "Expected return code 0" 0 "$result"
    assertContains "Expected the local file used" "$output" "Using local TE-file"
    assertNotContains "Expected no download" "$mock_log" "wget"
    assertContains "Expected the local file rewritten for sshd_session_t" "$mock_log" "allow sshd_session_t self:process { transition }; # local"
    assertContains "Expected the sshd_session_t module installed" "$output" "Installed module for sshd_session_t"
}

test_check_selinux_local_te_file_falls_back_to_sshd_t() {
    # A policy without sshd_session_t, such as RHEL and CentOS 9.
    mock_session_domain_unsupported=true
    LOCAL_TE_FILE="$TEST_TEMP_DIR/local.te"
    echo "module opkssh 2.0; require { type sshd_t; }; allow sshd_t self:process { transition }; # local" > "$LOCAL_TE_FILE"

    output=$(check_selinux 2>&1)
    result=$?
    mock_log=$(cat "$MOCK_LOG")

    assertEquals "Expected return code 0" 0 "$result"
    assertNotContains "Expected no download" "$mock_log" "wget"
    assertContains "Expected the local file installed as written" "$mock_log" "allow sshd_t self:process { transition }; # local"
    assertContains "Expected the sshd_t module installed" "$output" "Installed module for sshd_t"
}

test_check_selinux_records_policy_without_cache_type() {
    check_selinux >/dev/null 2>&1

    assertEquals "Expected the downloaded dummy policy to lack the cache type" "false" "$SELINUX_POLICY_SUPPORTS_CACHE"
    assertContains "Expected the release recorded" "$SELINUX_POLICY_SOURCE" "release "
}

test_check_selinux_records_policy_with_cache_type() {
    LOCAL_TE_FILE="$TEST_TEMP_DIR/local.te"
    echo "module opkssh 2.1; require { type sshd_t; }; type opkssh_cache_t;" > "$LOCAL_TE_FILE"

    check_selinux >/dev/null 2>&1

    assertEquals "Expected the local policy to have the cache type" "true" "$SELINUX_POLICY_SUPPORTS_CACHE"
    assertEquals "Expected the local file recorded" "the local file $LOCAL_TE_FILE" "$SELINUX_POLICY_SOURCE"
}

# shellcheck disable=SC1091
source shunit2
