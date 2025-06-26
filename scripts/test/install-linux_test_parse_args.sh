#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

# Setup for each test
setUp() {
    HOME_POLICY=true
    RESTART_SSH=true
    OVERWRITE_ACTIVE_CONFIG=false
    LOCAL_INSTALL_FILE=""
    INSTALL_VERSION="latest"
}

# Mock the help function
display_help_message() {
    echo "Help message shown"
}

test_parse_args_no_home_policy() {
    parse_args --no-home-policy
    assertEquals "Expected HOME_POLICY to be false" false "$HOME_POLICY"
}

test_parse_args_no_sshd_restart() {
    parse_args --no-sshd-restart
    assertEquals "Expected RESTART_SSH to be false" false "$RESTART_SSH"
}

test_parse_args_overwrite_config() {
    parse_args --overwrite-config
    assertEquals "Expected OVERWRITE_ACTIVE_CONFIG to be true" true "$OVERWRITE_ACTIVE_CONFIG"
}

test_parse_args_install_from() {
    parse_args --install-from=/path/to/file
    assertEquals "Expected LOCAL_INSTALL_FILE to be set" "/path/to/file" "$LOCAL_INSTALL_FILE"
}

test_parse_args_install_version() {
    parse_args --install-version=1.2.3
    assertEquals "Expected INSTALL_VERSION to be set" "1.2.3" "$INSTALL_VERSION"
}

test_parse_args_help_flag() {
    output=$(parse_args --help)
    result=$?
    assertEquals "Expected parse_args to return 1 on --help" 1 $result
    assertContains "Expected help message in output" "$output" "Help message shown"
}

# shellcheck disable=SC1091
source shunit2
