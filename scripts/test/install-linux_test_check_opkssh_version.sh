#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

test_check_opkssh_version_latest() {
    export INSTALL_VERSION="latest"

    output=$(check_opkssh_version)
    result=$?

    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected retur code to be 0" 0 $result

}

test_check_opkssh_version_0_10_0() {
    export INSTALL_VERSION="v0.10.0"

    output=$(check_opkssh_version)
    result=$?

    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected retur code to be 0" 0 $result

}

test_check_opkssh_version_100() {
    export INSTALL_VERSION="v1.0.0"

    output=$(check_opkssh_version)
    result=$?

    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected retur code to be 0" 0 $result

}

test_check_opkssh_version_080_different_repo() {
    export INSTALL_VERSION="v0.8.0"
    export GITHUB_REPO="foo/bar"

    output=$(check_opkssh_version 2>&1)
    result=$?

    assertContains "Expected URL to contain foo/bar" "$output" "foo/bar/refs/tags/v0.8.0"
    assertEquals "Expected retur code to be 1" 1 $result

}

test_check_opkssh_version_079() {
    export INSTALL_VERSION="v0.7.9"

    output=$(check_opkssh_version 2>&1)
    result=$?

    assertContains "Expected error message" "$output" "Installing opkssh v0.7.9 with this script"
    assertEquals "Expected retur code to be 1" 1 $result

}

# shellcheck disable=SC1091
source shunit2
