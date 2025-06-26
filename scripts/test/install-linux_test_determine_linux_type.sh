#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

#
# Override functions for mocking
#
file_exists() {
    [[ " ${mock_files[*]} " == *" $1 "* ]]
}

# Mock grep -q '^ID_LIKE=.*suse'
grep() {
    if [[ "$1" == "-q" && "$2" == "^ID_LIKE=.*suse" ]]; then
        if [[ "$mock_grep_suse" -eq 0 ]]; then
            return 0
        else
            return 1
        fi
    fi
    /usr/bin/grep "$@"
}

# Running tests

test_determine_linux_type_redhat() {
    mock_files=("/etc/redhat-release")
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return success (0) for /etc/redhat-release" 0 $result
    assertEquals "Expected the output to equal 'redhat' for /etc/redhat-release" "redhat" "$output"
}

test_determine_linux_type_debian() {
    mock_files=("/etc/debian_version")
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return success (0) for /etc/debian_version" 0 $result
    assertEquals "Expected the output to equal 'debian' for /etc/debian_version" "debian" "$output"
}

test_determine_linux_type_arch() {
    mock_files=("/etc/arch-release")
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return success (0) for /etc/arch-release" 0 $result
    assertEquals "Expected the output to equal 'arch' for /etc/arch-release" "arch" "$output"
}

test_determine_linux_type_suse() {
    mock_files=("/etc/os-release")
    mock_grep_suse=0
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return success (0) for /etc/os-release and greping 'ID_LIKE=suse'" 0 $result
    assertEquals "Expected the output to equal 'suse' for /etc/os-release" "suse" "$output"
}

test_determine_linux_type_os_release_non_suse() {
    mock_files=("/etc/os-release")
    mock_grep_suse="1"
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return failure (1) for /etc/os-release and greping 'ID_LIKE=ubuntu'" 1 $result
    assertEquals "Expected the output to equal 'Unsupported OS type.' for /etc/os-release greping 'ID_LIKE=ubuntu" "Unsupported OS type." "$output"
}

test_determine_linux_type_unsupported_os() {
    mock_files=()
    mock_grep_suse="0"
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return failure (1) for unknown file" 1 $result
    assertEquals "Expected the output to equal 'Unsupported OS type.' for unknonw file" "Unsupported OS type." "$output"
}

# shellcheck disable=SC1091
source shunit2
