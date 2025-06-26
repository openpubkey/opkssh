#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

# Running tests

test_running_as_root_uid_0() {
    output=$(running_as_root 0)
    result=$?
    assertEquals "Expected running_as_root to return success (0) for UID 0" 0 $?
    assertEquals "Expected running_as_root output to be empty '' for UID 0" "" "$output"
}

test_running_as_root_uid_1000() {
    output=$(running_as_root 1000 2>&1)
    result=$?
    assertEquals "Expected running_as_root to return failure (1) for UID 1000" 1 $result
    assertContains "Expected running_as_root to contain 'This script must be run as root' for UID 1000" "$output" "This script must be run as root"
}

# shellcheck disable=SC1091
source shunit2
