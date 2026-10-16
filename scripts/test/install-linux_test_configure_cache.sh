#!/bin/bash

export SHUNIT_RUNNING=1

# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""

setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    # Exported so configure_cache in the sourced script picks them up.
    export AUTH_CMD_USER="opksshuser"
    export AUTH_CMD_GROUP="opksshuser"
    export INSTALL_DIR="/usr/local/bin"
    export BINARY_NAME="opkssh"
    export CACHE_DIR=""
    export CACHE_CLEAN_ON_CALENDAR="daily"
    # The config.yml the cache section is appended to.
    mkdir -p "$TEST_TEMP_DIR/opk"
    touch "$TEST_TEMP_DIR/opk/config.yml"
}

tearDown() {
    /usr/bin/rm -rf "$TEST_TEMP_DIR"
}

# Mock commands so the test does not touch the real system.
install() {
    echo "install $*" >> "$MOCK_LOG"
    mkdir -p "${!#}"
}

runuser() {
    echo "runuser $*" >> "$MOCK_LOG"
    return "${runuser_exit_code:-0}"
}

systemctl() {
    echo "systemctl $*" >> "$MOCK_LOG"
}

# Tests

test_configure_cache_disabled_is_noop() {
    CACHE_DIR=""
    output=$(configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd")
    result=$?

    assertEquals "Expected to return 0 when disabled" 0 "$result"
    assertContains "Expected a skip message" "$output" "not requested"
    assertFalse "Expected no mock commands to run" "[ -f \"$MOCK_LOG\" ]"
    assertFalse "Expected no cache section added" "grep -q '^cache:' \"$TEST_TEMP_DIR/opk/config.yml\""
}

test_configure_cache_provisions_dir_config_and_timer() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"

    result=$(configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null; echo $?)

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertTrue "Expected cache directory to be created" "[ -d \"$CACHE_DIR\" ]"
    assertContains "Expected cache dir provisioned for the verification user" "${mock_log[*]}" "install -d -o ${AUTH_CMD_USER} -g ${AUTH_CMD_GROUP} -m 700 $CACHE_DIR"
    assertContains "Expected cache preflight run as the verification user" "${mock_log[*]}" "runuser -u ${AUTH_CMD_USER} -- ${INSTALL_DIR}/${BINARY_NAME} cache check"

    assertTrue "Expected cache section appended to config.yml" "grep -q '^cache:' \"$TEST_TEMP_DIR/opk/config.yml\""
    assertTrue "Expected base_dir written to config.yml" "grep -q 'base_dir: $CACHE_DIR' \"$TEST_TEMP_DIR/opk/config.yml\""

    assertTrue "Expected service unit written" "[ -f \"$TEST_TEMP_DIR/systemd/opkssh-cache-clean.service\" ]"
    assertTrue "Expected timer unit written" "[ -f \"$TEST_TEMP_DIR/systemd/opkssh-cache-clean.timer\" ]"
    assertContains "Expected daemon-reload" "${mock_log[*]}" "systemctl daemon-reload"
    assertContains "Expected timer enabled" "${mock_log[*]}" "systemctl enable --now opkssh-cache-clean.timer"
}

test_configure_cache_rejects_existing_cache_section() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"
    printf 'cache:\n  base_dir: /already/set\n' > "$TEST_TEMP_DIR/opk/config.yml"

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null
    result=$?

    assertEquals "Expected to reject an ambiguous cache configuration" 1 "$result"
    assertTrue "Expected existing base_dir kept" "grep -q 'base_dir: /already/set' \"$TEST_TEMP_DIR/opk/config.yml\""
    assertFalse "Expected no cache directory provisioned" "[ -d \"$CACHE_DIR\" ]"
}

test_configure_cache_accepts_matching_cache_section() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"
    printf 'cache:\n  base_dir: %s\n' "$CACHE_DIR" > "$TEST_TEMP_DIR/opk/config.yml"

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null
    result=$?

    assertEquals "Expected matching cache configuration to be accepted" 0 "$result"
    assertTrue "Expected cache directory provisioned" "[ -d \"$CACHE_DIR\" ]"
    assertContains "Expected cache preflight run" "$(cat "$MOCK_LOG")" "runuser -u ${AUTH_CMD_USER} -- ${INSTALL_DIR}/${BINARY_NAME} cache check"
}

test_configure_cache_rejects_unsafe_path() {
    CACHE_DIR="relative/cache"

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null
    result=$?

    assertEquals "Expected to reject a relative cache path" 1 "$result"
    assertFalse "Expected no cache section added" "grep -q '^cache:' \"$TEST_TEMP_DIR/opk/config.yml\""
}

# shellcheck disable=SC1091
source shunit2
