#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

setUp() {
    mock_command_found=true
    mock_getenforce="Enforcing"
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    touch "$MOCK_LOG"
    HOME_POLICY=true
    export HOME_POLICY
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
    expected_te_tmp=$(cat <<-END
module opkssh 1.0;


require {
        type sshd_t;
        type var_log_t;
        type ssh_exec_t;
        type http_port_t;
        type sudo_exec_t;
        class file { append execute execute_no_trans open read map };
        class tcp_socket name_connect;
}


# We need to allow the AuthorizedKeysCommand opkssh process launched by sshd to:

# 1. Make TCP connections to ports labeled http_port_t. This is so opkssh can download the public keys of the OpenID providers.
allow sshd_t http_port_t:tcp_socket name_connect;

# 2. Needed to allow opkssh to call \`ssh -V\` to determine if the version is supported by opkssh
allow sshd_t ssh_exec_t:file { execute execute_no_trans open read map };

# 3. Needed to allow opkssh to call \`sudo opkssh readhome\` to read the policy file in the user's home directory
allow sshd_t sudo_exec_t:file { execute execute_no_trans open read map };

# 4. Needed to allow opkssh to write to its log file
allow sshd_t var_log_t:file { open append };
END
)
    [[ "$mock_log" == *"$expected_te_tmp"* ]]
    te_tmp_result=$?
    assertEquals "Expected to return 0 when SELinux is active and home policy is used" 0 "$result"
    assertContains "Expected restorecon to use correct arguments" "$mock_log" "restorecon ${INSTALL_DIR}/${BINARY_NAME}"
    assertContains "Expected checkmodule to use correct arguments" "$mock_log" "checkmodule -M -m -o /tmp/opkssh.mod /tmp/opkssh.te"
    assertContains "Expected semodule_package to use correct arguments" "$mock_log" "semodule_package -o /tmp/opkssh.pp -m /tmp/opkssh.mod"
    assertContains "Expected semodule to use correct arguments" "$mock_log" "semodule -i /tmp/opkssh.pp"
    assertContains "Expected rm to use correct arguments" "$mock_log" "rm -f /tmp/opkssh.te /tmp/opkssh.mod /tmp/opkssh.pp"
    assertEquals "Expected TE_TMP to contain the correct information" 0 "$te_tmp_result"

}


test_check_selinux_no_home_policy() {
    HOME_POLICY=false
    output=$(check_selinux 2>&1)
    result=$?
    mock_log=$(cat "$MOCK_LOG")
    expected_te_tmp=$(cat <<-END
module opkssh-no-home 1.0;

require {
        type sshd_t;
        type var_log_t;
        type ssh_exec_t;
        type http_port_t;
        class file { append execute execute_no_trans open read map };
        class tcp_socket name_connect;
}


# We need to allow the AuthorizedKeysCommand opkssh process launched by sshd to:

# 1. Make TCP connections to ports labeled http_port_t. This is so opkssh can download the public keys of the OpenID providers.
allow sshd_t http_port_t:tcp_socket name_connect;

# 2. Needed to allow opkssh to call \`ssh -V\` to determine if the version is supported by opkssh
allow sshd_t ssh_exec_t:file { execute execute_no_trans open read map };

# 3. Needed to allow opkssh to write to its log file
allow sshd_t var_log_t:file { open append };
semodule_package -o /tmp/opkssh-no-home.pp -m /tmp/opkssh-no-home.mod
semodule -i /tmp/opkssh-no-home.pp
rm -f /tmp/opkssh-no-home.te /tmp/opkssh-no-home.mod /tmp/opkssh-no-home.pp
END
)

    [[ "$mock_log" == *"$expected_te_tmp"* ]]
    te_tmp_result=$?
    assertEquals "Expected to return 0 when SELinux is active and home policy is NOT used" 0 "$result"
    assertContains "Expected restorecon to use correct arguments" "$mock_log" "restorecon ${INSTALL_DIR}/${BINARY_NAME}"
    assertContains "Expected checkmodule to use correct arguments" "$mock_log" "checkmodule -M -m -o /tmp/opkssh-no-home.mod /tmp/opkssh-no-home.te"
    assertContains "Expected semodule_package to use correct arguments" "$mock_log" "semodule_package -o /tmp/opkssh-no-home.pp -m /tmp/opkssh-no-home.mod"
    assertContains "Expected semodule to use correct arguments" "$mock_log" "semodule -i /tmp/opkssh-no-home.pp"
    assertContains "Expected rm to use correct arguments" "$mock_log" "rm -f /tmp/opkssh-no-home.te /tmp/opkssh-no-home.mod /tmp/opkssh-no-home.pp"
    assertEquals "Expected TE_TMP to contain the correct information" 0 "$te_tmp_result"
}

# shellcheck disable=SC1091
source shunit2
