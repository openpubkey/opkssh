#!/bin/bash

export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""

setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    RESTART_SSH=true
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
}

tearDown() {
    /usr/bin/rm -rf "$TEST_TEMP_DIR"
}

systemctl() {
    echo "systemctl $*" >> "$MOCK_LOG"
}

# Tests

test_restart_openssh_server_no_restart() {
    export RESTART_SSH=false

    output=$(restart_openssh_server)
    result=$?

    assertEquals "Expected result 0 on success" 0 "$result"
    assertContains "Expected output to inform about skipping openSSH server restart" "$output" "skipping SSH restart"
    assertTrue "Expected that systemctl isn't called" "[ ! -f \"$TEST_TEMP_DIR/mock.log\" ]"
}

test_restart_openssh_server_redhat() {
    export OS_TYPE="redhat"
    output=$(restart_openssh_server)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertEquals "Expected systemctl to have correct parameters" "systemctl restart sshd" "${mock_log[0]}"
    assertEquals "Expected only one command to be called" 1 "${#mock_log[@]}"
}

test_restart_openssh_server_suse() {
    export OS_TYPE="suse"
    output=$(restart_openssh_server)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertEquals "Expected systemctl to have correct parameters" "systemctl restart sshd" "${mock_log[0]}"
    assertEquals "Expected only one command to be called" 1 "${#mock_log[@]}"
}


test_restart_openssh_server_debian() {
    export OS_TYPE="debian"
    output=$(restart_openssh_server)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertEquals "Expected systemctl to have correct parameters" "systemctl restart ssh" "${mock_log[0]}"
    assertEquals "Expected only one command to be called" 1 "${#mock_log[@]}"
}

test_restart_openssh_server_arch() {
    export OS_TYPE="arch"
    output=$(restart_openssh_server)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertEquals "Expected systemctl to have correct parameters" "systemctl restart sshd" "${mock_log[0]}"
    assertEquals "Expected only one command to be called" 1 "${#mock_log[@]}"
}

test_restart_openssh_server_unsupported_os() {
    export OS_TYPE="FooBar"
    output=$(restart_openssh_server)
    result=$?

    assertEquals "Expected result to be 1 on failure" 1 "$result"
    assertTrue "Expected that systemctl isn't called" "[ ! -f \"$TEST_TEMP_DIR/mock.log\" ]"
    assertContains "Expected to inform about unsupported OS" "$output" "$output"

}

# shellcheck disable=SC1091
source shunit2
