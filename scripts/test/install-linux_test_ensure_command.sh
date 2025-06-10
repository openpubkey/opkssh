#!/bin/bash
export SHUNIT_RUNNIN=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

#
# Override functions for mocking
#
command() {
    if [[ "$1" == "-v" && "$2" == "$mock_command_name" ]]; then
        if [[ "$mock_command_exists" == "true" ]]; then
            echo "/usr/bin/$2"
            return 0
        else
            return 1
        fi
    fi
    builtin command "$@"  # fall back to real command
}


# Running tests

test_ensure_command_exists() {
    mock_command_name="curl"
    mock_command_exists=true
    output=$(ensure_command "curl" "curl" "debian" 2>&1)
    result=$?
    assertEquals "Expected ensure_command_exists to return 0 when command exists" 0 $result
    assertEquals "Expected ensure_command_exists to not output anything when command exists" "" "$output"
}

test_ensure_command_missing_using_variables() {
    mock_command_name="foobar"
    mock_command_exists=false
    # shellcheck disable=2034  # used in ensure_command
    OS_TYPE=suse
    output=$(ensure_command "foobar" 2>&1)
    result=$?
    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to prompt to install on suse" "$output" "sudo zypper install foobar"
}

test_ensure_command_missing_debian() {
    mock_command_name="curl"
    mock_command_exists=false
    output=$(ensure_command "curl" "curl" "debian" 2>&1)
    result=$?
    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to prompt to install on debian" "$output" "sudo apt install curl"
}

test_ensure_command_missing_redhat_with_dnf() {
    mock_command_name="curl"
    mock_command_exists=false
    # Also mock dnf existence
    # shellcheck disable=2317
    command() {
        if [[ "$1" == "-v" && "$2" == "dnf" ]]; then
            return 0  # dnf exists
        fi
        if [[ "$1" == "-v" && "$2" == "$mock_command_name" ]]; then
            return 1  # command is missing
        fi
        builtin command "$@"
    }
    output=$(ensure_command "curl" "curl" "redhat" 2>&1)
    result=$?
    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to suggest dnf for redhat if available" "$output" "sudo dnf install curl"
}


test_ensure_command_missing_redhat_without_dnf() {
    mock_command_name="curl"
    mock_command_exists=false
    # Also mock dnf existence
    # shellcheck disable=2317
    command() {
        if [[ "$1" == "-v" && "$2" == "dnf" ]]; then
            return 1  # dnf is missing
        fi
        if [[ "$1" == "-v" && "$2" == "$mock_command_name" ]]; then
            return 1  # command is missing
        fi
        builtin command "$@"
    }
    output=$(ensure_command "curl" "curl" "redhat" 2>&1)
    result=$?
    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to suggest dnf for redhat if available" "$output" "sudo yum install curl"
}

test_ensure_command_missing_arch() {
    mock_command_name="curl"
    mock_command_exists=false
    output=$(ensure_command "curl" "curl" "arch" 2>&1)
    result=$?
    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to suggest pacman for arch" "$output" "sudo pacman -S curl"
}

test_ensure_command_missing_suse() {
    mock_command_name="curl"
    mock_command_exists=false
    output=$(ensure_command "curl" "curl" "suse" 2>&1)
    result=$?
    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to suggest zypper for suse" "$output" "sudo zypper install curl"
}

test_ensure_command_unsupported_os() {
    mock_command_name="curl"
    mock_command_exists=true
    output=$(ensure_command "curl" "curl" "foobar" 2>&1)
    result=$?
    assertEquals "Expected ensure_command_exists to return 1 when it is an Unsupported OS" 1 $result
    assertContains "Expected ensure_command_exists to warn about unsupported OS" "$output" "Unsupported OS type."
}

# shellcheck disable=SC1091
source shunit2
