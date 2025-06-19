#!/bin/bash

export SHUNIT_RUNNIN=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""

setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
}

tearDown() {
    /usr/bin/rm -rf "$TEST_TEMP_DIR"
}

# Mock commands
chown() {
    echo "chown $*" >> "$MOCK_LOG"
}

chmod() {
    echo "chmod $*" >> "$MOCK_LOG"
}

# Tests

test_configure_opkssh_no_previous_configuration() {
    # Define the default OpenID Providers
    local provider_google="https://accounts.google.com 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com 24h"
    local provider_microsoft="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h"
    local provider_gitlab="https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h"
    local provider_hello="https://issuer.hello.coop app_xejobTKEsDNSRd5vofKB2iay_2rN 24h"

    output=$(configure_opkssh "$TEST_TEMP_DIR")
    result=$?
    readarray -t mock_log < "$MOCK_LOG"
    readarray -t providers < "$TEST_TEMP_DIR/opk/providers"

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertEquals "Output was not expected" "Configuring opkssh:" "$output"
    assertTrue "Expected /etc/opk direcotry to be created" "[ -d \"$TEST_TEMP_DIR\"/opk ]"
    assertContains "Expected /etc/opk to set the correct ownership" "${mock_log[*]}" "chown root:${AUTH_CMD_GROUP} $TEST_TEMP_DIR/opk"
    assertContains "Expected /etc/opk to set the correct permission" "${mock_log[*]}" "chmod 750 $TEST_TEMP_DIR/opk"

    assertTrue "Expected /etc/opk/policy.d direcotry to be created" "[ -d \"$TEST_TEMP_DIR\"/opk/policy.d ]"
    assertContains "Expected /etc/opk/policy.d to set the correct ownership" "${mock_log[*]}" "chown root:${AUTH_CMD_GROUP} $TEST_TEMP_DIR/opk/policy.d"
    assertContains "Expected /etc/opk/policy.d to set the correct permission" "${mock_log[*]}" "chmod 750 $TEST_TEMP_DIR/opk/policy.d"

    assertTrue "Expected /etc/opk/auth_id file to be created" "[ -f \"$TEST_TEMP_DIR\"/opk/auth_id ]"
    assertContains "Expected /etc/opk/auth_id to set the correct ownership" "${mock_log[*]}" "chown root:${AUTH_CMD_GROUP} $TEST_TEMP_DIR/opk/auth_id"
    assertContains "Expected /etc/opk/auth_id to set the correct permission" "${mock_log[*]}" "chmod 640 $TEST_TEMP_DIR/opk/auth_id"

    assertTrue "Expected /etc/opk/config.yaml file to be created" "[ -f \"$TEST_TEMP_DIR\"/opk/config.yml ]"
    assertContains "Expected /etc/opk/config.yaml to set the correct ownership" "${mock_log[*]}" "chown root:${AUTH_CMD_GROUP} $TEST_TEMP_DIR/opk/config.yml"
    assertContains "Expected /etc/opk/config.yaml to set the correct permission" "${mock_log[*]}" "chmod 640 $TEST_TEMP_DIR/opk/config.yml"

    assertTrue "Expected /etc/opk/providers file to be created" "[ -f \"$TEST_TEMP_DIR\"/opk/providers ]"
    assertContains "Expected /etc/opk/providers to set the correct ownership" "${mock_log[*]}" "chown root:${AUTH_CMD_GROUP} $TEST_TEMP_DIR/opk/providers"
    assertContains "Expected /etc/opk/providers to set the correct permission" "${mock_log[*]}" "chmod 640 $TEST_TEMP_DIR/opk/providers"

    assertEquals "Expected first provider to be Google" "$provider_google" "${providers[0]}"
    assertEquals "Expected second provider to be Microsoft" "$provider_microsoft" "${providers[1]}"
    assertEquals "Expected third provider to be GitLab" "$provider_gitlab" "${providers[2]}"
    assertEquals "Expected forth provider to be GitLab" "$provider_hello" "${providers[3]}"
    assertEquals "Expected to have four providers" 4 "${#providers[@]}"
}

test_configure_opkssh_existing_providers() {
    mkdir -p "$TEST_TEMP_DIR/opk"
    echo "provider foo" >> "$TEST_TEMP_DIR/opk/providers"
    echo "provider bar" >> "$TEST_TEMP_DIR/opk/providers"
    output=$(configure_opkssh "$TEST_TEMP_DIR")
    result=$?

    readarray -t providers < "$TEST_TEMP_DIR/opk/providers"
    assertEquals "Expected to return 0 on success" 0 "$result"
    assertContains "Expected output to inform about not adding providers" "$output" "Keeping existing values"
    assertEquals "Expected to have two providers" 2 "${#providers[@]}"
    assertEquals "Expected first provider to be foo" "provider foo" "${providers[0]}"
    assertEquals "Expected first provider to be bar" "provider bar" "${providers[1]}"
}

# shellcheck disable=SC1091
source shunit2
