#!/bin/bash
export SHUNIT_RUNNIN=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

#
# Override functions for mocking
#
uname() {
    if [[ "$1" == "-m" ]]; then
        echo "$mock_uname_arch"
        return 0
    fi
    /usr/bin/uname "$@"
}

# Running tests

test_check_cpu_architecture_x86_64() {
    mock_uname_arch="x86_64"
    output=$(check_cpu_architecture)
    result=$?
    assertEquals "Expected check_cpu_architecture to return success (0) for x86_64 architecture" 0 $result
    assertEquals "Expected check_cpu_architecture to equal 'amd64' for x86_64 architecture" "amd64" "$output"
}

test_check_cpu_architecture_aarch64() {
    mock_uname_arch="aarch64"
    output=$(check_cpu_architecture)
    result=$?
    assertEquals "Expected check_cpu_architecture to return success (0) for aarch64 architecture" 0 $result
    assertEquals "Expected check_cpu_architecture to equal 'arm64' for x86_64 architecture" "arm64" "$output"
}

test_check_cpu_architecture_amd64() {
    mock_uname_arch="amd64"
    output=$(check_cpu_architecture)
    result=$?
    assertEquals "Expected check_cpu_architecture to return success (0) for amd64 architecture" 0 $result
    assertEquals "Expected check_cpu_architecture to equal 'amd64' for amd64 architecture" "amd64" "$output"
}

test_check_cpu_architecture_arm64() {
    mock_uname_arch="arm64"
    output=$(check_cpu_architecture)
    result=$?
    assertEquals "Expected check_cpu_architecture to return success (0) for arm64 architecture" 0 $result
    assertEquals "Expected check_cpu_architecture to equal 'arm64' for arm64 architecture" "arm64" "$output"
}

test_check_cpu_architecture_foobar() {
    mock_uname_arch="foobar"
    output=$(check_cpu_architecture 2>&1)
    result=$?
    assertEquals "Expected check_cpu_architecture to return failure (1) for foobar architecture" 1 $result
    assertContains "Expected check_cpu_architecture to contain 'Unsupported' for foobar architecture" "$output" "Unsupported"
}

# shellcheck disable=SC1091
source shunit2
