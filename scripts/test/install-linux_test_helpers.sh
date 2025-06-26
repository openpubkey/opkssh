#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

setUp() {
    TEST_DIR=$(mktemp -d)
    TEST_FILE="$TEST_DIR/sample.txt"
    mkdir "$TEST_DIR/subdir"
    touch "$TEST_FILE"
}

tearDown() {
    rm -rf "$TEST_DIR"
}

# Test file_exists
test_file_exists_returns_true_for_file() {
    file_exists "$TEST_FILE"
    assertTrue "Expected file_exists to return true for existing file" $?
}

test_file_exists_returns_false_for_missing_file() {
    file_exists "$TEST_DIR/nope.txt"
    assertFalse "Expected file_exists to return false for non-existent file" $?
}

test_file_exists_returns_false_for_directory() {
    file_exists "$TEST_DIR/subdir"
    assertFalse "Expected file_exists to return false for a directory" $?
}

# Test dir_exists
test_dir_exists_returns_true_for_directory() {
    dir_exists "$TEST_DIR/subdir"
    assertTrue "Expected dir_exists to return true for directory" $?
}

test_dir_exists_returns_false_for_file() {
    dir_exists "$TEST_FILE"
    assertFalse "Expected dir_exists to return false for a file" $?
}

test_dir_exists_returns_false_for_missing_path() {
    dir_exists "$TEST_DIR/ghost"
    assertFalse "Expected dir_exists to return false for non-existent path" $?
}

# shellcheck disable=SC1091
source shunit2
