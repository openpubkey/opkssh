#!/bin/bash

export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""

setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    LOCAL_PROVIDERS_FILE=""
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

# active_provider_lines
# Prints the lines opkssh would read as providers: comments and blank lines removed
active_provider_lines() {
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$1"
}

# Tests

test_configure_opkssh_no_previous_configuration() {
    output=$(configure_opkssh "$TEST_TEMP_DIR")
    result=$?
    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertContains "Output was not expected" "$output" "Configuring opkssh:"
    assertContains "Expected output to say no provider is enabled" "$output" "No OpenID Provider is enabled yet"
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

    assertEquals "Expected providers file to be the template" "$(providers_template)" "$(cat "$TEST_TEMP_DIR/opk/providers")"
    assertEquals "Expected no provider to be enabled" "" "$(active_provider_lines "$TEST_TEMP_DIR/opk/providers")"
    assertContains "Expected the template to list Google" "$(cat "$TEST_TEMP_DIR/opk/providers")" "# https://accounts.google.com <CLIENT-ID> 24h"
    assertNotContains "Expected no default client ID" "$(cat "$TEST_TEMP_DIR/opk/providers")" "206584157355"
}

test_configure_opkssh_template_accepts_appended_provider() {
    # CI and the integration tests enable a provider by appending a line
    configure_opkssh "$TEST_TEMP_DIR" > /dev/null
    echo "https://oidc.example.com my-client-id 24h" >> "$TEST_TEMP_DIR/opk/providers"

    assertEquals "Expected the appended line to be the only provider" \
        "https://oidc.example.com my-client-id 24h" \
        "$(active_provider_lines "$TEST_TEMP_DIR/opk/providers")"
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

test_configure_opkssh_local_providers_file() {
    LOCAL_PROVIDERS_FILE="$TEST_TEMP_DIR/my-providers"
    printf '%s\n' "# my providers" "https://accounts.google.com my-client-id 24h" > "$LOCAL_PROVIDERS_FILE"

    output=$(configure_opkssh "$TEST_TEMP_DIR")
    result=$?
    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertContains "Expected output to name the local file" "$output" "Writing providers from $LOCAL_PROVIDERS_FILE"
    assertEquals "Expected providers file to be a copy of the local file" "$(cat "$LOCAL_PROVIDERS_FILE")" "$(cat "$TEST_TEMP_DIR/opk/providers")"
    assertContains "Expected /etc/opk/providers to set the correct ownership" "${mock_log[*]}" "chown root:${AUTH_CMD_GROUP} $TEST_TEMP_DIR/opk/providers"
    assertContains "Expected /etc/opk/providers to set the correct permission" "${mock_log[*]}" "chmod 640 $TEST_TEMP_DIR/opk/providers"
}

test_configure_opkssh_local_providers_file_without_trailing_newline() {
    LOCAL_PROVIDERS_FILE="$TEST_TEMP_DIR/my-providers"
    printf '%s' "https://accounts.google.com my-client-id 24h" > "$LOCAL_PROVIDERS_FILE"

    configure_opkssh "$TEST_TEMP_DIR" > /dev/null
    echo "https://oidc.example.com other-client-id 24h" >> "$TEST_TEMP_DIR/opk/providers"

    readarray -t providers < <(active_provider_lines "$TEST_TEMP_DIR/opk/providers")
    assertEquals "Expected two providers" 2 "${#providers[@]}"
    assertEquals "Expected the appended provider on its own line" "https://oidc.example.com other-client-id 24h" "${providers[1]}"
}

test_configure_opkssh_local_providers_file_keeps_existing_providers() {
    mkdir -p "$TEST_TEMP_DIR/opk"
    echo "provider foo" > "$TEST_TEMP_DIR/opk/providers"
    LOCAL_PROVIDERS_FILE="$TEST_TEMP_DIR/my-providers"
    echo "https://accounts.google.com my-client-id 24h" > "$LOCAL_PROVIDERS_FILE"

    output=$(configure_opkssh "$TEST_TEMP_DIR")

    assertContains "Expected output to inform about keeping providers" "$output" "Keeping existing values"
    assertContains "Expected output to say the local file is not used" "$output" "Not using $LOCAL_PROVIDERS_FILE"
    assertEquals "Expected existing providers to be kept" "provider foo" "$(cat "$TEST_TEMP_DIR/opk/providers")"
}

test_check_local_providers_file_not_set() {
    check_local_providers_file
    assertEquals "Expected success when no providers file is given" 0 $?
}

test_check_local_providers_file_exists() {
    LOCAL_PROVIDERS_FILE="$TEST_TEMP_DIR/my-providers"
    touch "$LOCAL_PROVIDERS_FILE"
    check_local_providers_file
    assertEquals "Expected success when the providers file exists" 0 $?
}

test_check_local_providers_file_missing() {
    LOCAL_PROVIDERS_FILE="$TEST_TEMP_DIR/does-not-exist"
    output=$(check_local_providers_file 2>&1)
    result=$?
    assertEquals "Expected failure when the providers file does not exist" 1 "$result"
    assertContains "Expected an error naming the file" "$output" "Error: Specified providers file does not exist: $LOCAL_PROVIDERS_FILE"
}

# shellcheck disable=SC1091
source shunit2
