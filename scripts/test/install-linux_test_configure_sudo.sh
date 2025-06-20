#!/bin/bash

export SHUNIT_RUNNIN=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""

setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    HOME_POLICY=true
    SUDOERS_PATH="$TEST_TEMP_DIR/sudo"
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    export SUDOERS_PATH HOME_POLICY
}

tearDown() {
    /usr/bin/rm -rf "$TEST_TEMP_DIR"
}

chmod() {
    echo "chmod $*" >> "$MOCK_LOG"
}

# Tests

test_configure_sudo_no_existing_file() {
    output=$(configure_sudo)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    readarray -t sudo_content < "$SUDOERS_PATH"

    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertContains "Expected output to inform about creating sudo file" "$output" "Creating sudoers file at"
    assertContains "Expected output to contain information about adding sudo rule" "$output" "Adding sudoers rule for"
    assertTrue "Expected sudo file to be created" "[ -f \"$SUDOERS_PATH\" ]"
    assertContains "Expected sudo file to be configured with correct permissions" "chmod 440 $SUDOERS_PATH" "${mock_log[*]}"
    assertEquals "Expected sudo rule to be configured correctly" "${sudo_content[1]}" "$AUTH_CMD_USER ALL=(ALL) NOPASSWD: ${INSTALL_DIR}/${BINARY_NAME} readhome *"
    assertEquals "Expected sudo file to contain two rows" 2 "${#sudo_content[@]}"
}

test_configure_sudo_existing_file_no_opkssh_entry() {
    echo "# This is a comment" > "$SUDOERS_PATH"
    output=$(configure_sudo)
    result=$?

    readarray -t sudo_content < "$SUDOERS_PATH"

    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertContains "Expected output to contain information about adding sudo rule" "$output" "Adding sudoers rule for"
    assertTrue "Expected sudo file to exist" "[ -f \"$SUDOERS_PATH\" ]"
    assertContains "Expected sudo rule to be configured correctly" "${sudo_content[*]}" "$AUTH_CMD_USER ALL=(ALL) NOPASSWD: ${INSTALL_DIR}/${BINARY_NAME} readhome *"
    assertEquals "Expected sudo file to contain three rows" 3 "${#sudo_content[@]}"
}

test_configure_sudo_existing_file_with_opkssh_entry() {
    echo "$AUTH_CMD_USER ALL=(ALL) NOPASSWD: ${INSTALL_DIR}/${BINARY_NAME} readhome *" >> "$SUDOERS_PATH"
    output=$(configure_sudo)
    result=$?

    readarray -t sudo_content < "$SUDOERS_PATH"

    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertContains "Expected output to be empty" "" "$output"
    assertTrue "Expected sudo file to exist" "[ -f \"$SUDOERS_PATH\" ]"
    assertContains "Expected sudo rule to be configured correctly" "$AUTH_CMD_USER ALL=(ALL) NOPASSWD: ${INSTALL_DIR}/${BINARY_NAME} readhome *" "${sudo_content[0]}"
    assertEquals "Expected sudo file to contain one rows" 1 "${#sudo_content[@]}"
}

test_configure_sudo_no_home_policy() {
    HOME_POLICY=false
    output=$(configure_sudo)
    result=$?

    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertContains "Expected output to contain information about skipping sudo configuration" "$output" "Skipping sudoers configuration"
    assertTrue "Expected sudo file to not exist" "[ ! -f \"$SUDOERS_PATH\" ]"
}

# shellcheck disable=SC1091
source shunit2
