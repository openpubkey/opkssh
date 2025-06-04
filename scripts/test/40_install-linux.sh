#!/bin/bash
export SHUNIT_RUNNIN=1

echo "Running tests: ${0##*/}"

# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

# Setup for each test
setUp() {
    mock_group_exists=false
    mock_user_exists=false
    mock_groupadd_called=false
    mock_useradd_called=false
    mock_usermod_called=false
    mock_log=()
    # Reset global vars before each test
    HOME_POLICY=true
    RESTART_SSH=true
    OVERWRITE_ACTIVE_CONFIG=false
    LOCAL_INSTALL_FILE=""
    INSTALL_VERSION="latest"
}

# Mocking getent
getent() {
    if [[ "$1" == "group" ]]; then
        $mock_group_exists && return 0 || return 1
    elif [[ "$1" == "passwd" ]]; then
        $mock_user_exists && return 0 || return 1
    fi
    return 1
}

# Mocking groupadd
groupadd() {
    mock_groupadd_called=true
    mock_log+=("groupadd $*")
}

# Mocking useradd
useradd() {
    mock_useradd_called=true
    mock_log+=("useradd $*")
}

# Mocking usermod
usermod() {
    mock_usermod_called=true
    mock_log+=("usermod $*")
}

# Mock the help function
display_help_message() {
    echo "Help message shown"
}

# Running tests
test_ensure_opkssh_user_and_group_ensure_user_and_group_created_if_not_exists() {
    mock_group_exists=false
    mock_user_exists=false

    ensure_opkssh_user_and_group "testuser" "testgroup" > /dev/null

    assertEquals "Expected groupadd to be called" true "$mock_groupadd_called"
    assertEquals "Expected useradd to be called" true "$mock_useradd_called"
    assertEquals "Expected usermod NOT to be called" false "$mock_usermod_called"
    assertContains "Expected useradd to be called with correct arguments" "${mock_log[*]}" \
        "useradd -r -M -s /sbin/nologin -g testgroup testuser"
    assertContains "Expected useradd to be called with correct arguments" "${mock_log[*]}" \
        "useradd -r -M -s /sbin/nologin -g testgroup testuser"
}

test_ensure_opkssh_user_and_group_ensure_user_created_if_group_exists() {
    mock_group_exists=true
    mock_user_exists=false

    ensure_opkssh_user_and_group "testuser" "testgroup" > /dev/null

    assertEquals "Expected groupadd NOT to be called" false "$mock_groupadd_called"
    assertEquals "Expected useradd to be called" true "$mock_useradd_called"
    assertEquals "Expected usermod NOT to be called" false "$mock_usermod_called"
    assertContains "Expected useradd to be called with correct arguments" "${mock_log[*]}" \
        "useradd -r -M -s /sbin/nologin -g testgroup testuser"
}

test_ensure_opkssh_user_and_group_ensure_usermod_called_if_user_exists() {
    mock_group_exists=true
    mock_user_exists=true

    ensure_opkssh_user_and_group "testuser" "testgroup" > /dev/null

    assertEquals "Expected groupadd NOT to be called" false "$mock_groupadd_called"
    assertEquals "Expected useradd NOT to be called" false "$mock_useradd_called"
    assertEquals "Expected usermod to be called" true "$mock_usermod_called"
    assertContains "Expected usermod to be called with correct arguments" "${mock_log[*]}" \
        "usermod -aG testgroup testuser"
}

test_ensure_opkssh_user_and_group_no_action_if_user_and_group_exist() {
    mock_group_exists=true
    mock_user_exists=true

    ensure_opkssh_user_and_group "testuser" "testgroup" > /dev/null

    assertEquals "Expected groupadd NOT to be called" false "$mock_groupadd_called"
    assertEquals "Expected useradd NOT to be called" false "$mock_useradd_called"
    assertEquals "Expected usermod to be called" true "$mock_usermod_called"
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
