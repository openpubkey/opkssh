#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

# Running tests

test_check_bash_version_4_1() {
    output=$(check_bash_version 4 1)
    result=$?
    assertEquals "Expected check_bash_version to return success (0) for version 4.1" 0 $result
    assertContains "Expected output to include '4.1' when checking bash version 4.1" "$output" "4.1"
}

test_check_bash_version_3_2() {
    output=$(check_bash_version 3 2)
    result=$?
    assertEquals "Expected check_bash_version to return success (0) for version 3.2" 0 $result
    assertContains "Expected output to include '4.1' when checking bash version 3.2" "$output" "3.2"
}

test_check_bash_version_3_1_2() {
    output=$(check_bash_version 3 1 2>&1)
    result=$?
    assertEquals "Expected check_bash_version to return failure (1) for unsupported version 3.1.2" 1 $result
    assertContains "Expected error message to mention 'Unsupported Bash version'" "$output" "Unsupported Bash version"
}

# shellcheck disable=SC1091
source shunit2
