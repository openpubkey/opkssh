#!/bin/bash
export SHUNIT_RUNNING=1


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

# shellcheck disable=SC1091
source shunit2
