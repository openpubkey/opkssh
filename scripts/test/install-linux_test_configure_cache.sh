#!/bin/bash

export SHUNIT_RUNNING=1

# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""

setUp() {
    selinux_enabled_exit_code=1
    systemd_running_exit_code=0
    semanage_available_exit_code=0
    semanage_add_exit_code=0
    runuser_exit_code=0
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

# By default SELinux is disabled and systemd is running. Tests override these.
selinux_enabled() {
    return "${selinux_enabled_exit_code:-1}"
}

systemd_running() {
    return "${systemd_running_exit_code:-0}"
}

semanage_available() {
    return "${semanage_available_exit_code:-0}"
}

semanage() {
    echo "semanage $*" >> "$MOCK_LOG"
    if [[ "$2" == "-a" ]]; then
        return "${semanage_add_exit_code:-0}"
    fi
    return 0
}

restorecon() {
    echo "restorecon $*" >> "$MOCK_LOG"
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

test_configure_cache_preflights_new_config_before_replacing() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null
    result=$?

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertContains "Expected the preflight to check the new config, not the live one" "$(cat "$MOCK_LOG")" "cache check --config-path $TEST_TEMP_DIR/opk/config.yml.opkssh-new"
    assertFalse "Expected the temporary config to be moved into place" "[ -e \"$TEST_TEMP_DIR/opk/config.yml.opkssh-new\" ]"
}

test_configure_cache_adds_newline_before_section() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"
    printf 'deny_users:\n  - bob' > "$TEST_TEMP_DIR/opk/config.yml"

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null
    result=$?

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertTrue "Expected the last existing line to be kept intact" "grep -qx '  - bob' \"$TEST_TEMP_DIR/opk/config.yml\""
    assertTrue "Expected cache: on its own line" "grep -qx 'cache:' \"$TEST_TEMP_DIR/opk/config.yml\""
}

test_configure_cache_failed_preflight_leaves_config_unchanged() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"
    printf 'deny_users:\n  - bob' > "$TEST_TEMP_DIR/opk/config.yml"
    cp "$TEST_TEMP_DIR/opk/config.yml" "$TEST_TEMP_DIR/original.yml"
    runuser_exit_code=1

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null
    result=$?
    runuser_exit_code=0

    assertEquals "Expected to return 1 when the preflight fails" 1 "$result"
    assertTrue "Expected config.yml to be byte-for-byte unchanged" "cmp -s \"$TEST_TEMP_DIR/original.yml\" \"$TEST_TEMP_DIR/opk/config.yml\""
    assertFalse "Expected the temporary config to be removed" "[ -e \"$TEST_TEMP_DIR/opk/config.yml.opkssh-new\" ]"
    assertFalse "Expected no timer to be installed" "[ -f \"$TEST_TEMP_DIR/systemd/opkssh-cache-clean.timer\" ]"
}

test_configure_cache_labels_dir_for_selinux_before_preflight() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"
    selinux_enabled_exit_code=0

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    assertEquals "Expected to return 0 on success" 0 "$result"
    assertContains "Expected the cache dir file context set" "${mock_log[*]}" "semanage fcontext -a -t opkssh_cache_t ${CACHE_DIR//./\\.}(/.*)?"
    assertContains "Expected the cache dir relabelled" "${mock_log[*]}" "restorecon -R $CACHE_DIR"

    local install_line semanage_line restorecon_line runuser_line i
    for i in "${!mock_log[@]}"; do
        case "${mock_log[$i]}" in
            install*) install_line=$i ;;
            semanage*) semanage_line=$i ;;
            restorecon*) restorecon_line=$i ;;
            runuser*) runuser_line=$i ;;
        esac
    done
    assertTrue "Expected the dir created before it is labelled" "[ $install_line -lt $semanage_line ]"
    assertTrue "Expected semanage before restorecon" "[ $semanage_line -lt $restorecon_line ]"
    assertTrue "Expected labelling before the preflight, which checks the label" "[ $restorecon_line -lt $runuser_line ]"
}

test_configure_cache_escapes_dots_in_selinux_path() {
    CACHE_DIR="$TEST_TEMP_DIR/opk.cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"
    selinux_enabled_exit_code=0

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null

    local semanage_call
    semanage_call=$(grep '^semanage fcontext -a' "$MOCK_LOG")
    assertContains "Expected the dot escaped in the semanage regex" "$semanage_call" '/opk\.cache(/.*)?'
    assertNotContains "Expected no unescaped dot" "$semanage_call" '/opk.cache'
}

test_configure_cache_modifies_existing_selinux_rule() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"
    selinux_enabled_exit_code=0
    semanage_add_exit_code=1

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null
    result=$?

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertContains "Expected an existing rule to be modified" "$(cat "$MOCK_LOG")" "semanage fcontext -m -t opkssh_cache_t ${CACHE_DIR//./\\.}(/.*)?"
}

test_configure_cache_selinux_without_semanage_fails_safely() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"
    printf 'deny_users:\n  - bob\n' > "$TEST_TEMP_DIR/opk/config.yml"
    cp "$TEST_TEMP_DIR/opk/config.yml" "$TEST_TEMP_DIR/original.yml"
    selinux_enabled_exit_code=0
    semanage_available_exit_code=1

    output=$(configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd")
    result=$?

    assertEquals "Expected to fail without semanage" 1 "$result"
    assertContains "Expected the missing package named" "$output" "policycoreutils-python-utils"
    assertTrue "Expected config.yml unchanged" "cmp -s \"$TEST_TEMP_DIR/original.yml\" \"$TEST_TEMP_DIR/opk/config.yml\""
    assertNotContains "Expected no preflight" "$(cat "$MOCK_LOG")" "runuser"
}

test_configure_cache_skips_selinux_when_disabled() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null

    assertNotContains "Expected no semanage call" "$(cat "$MOCK_LOG")" "semanage"
    assertNotContains "Expected no restorecon call" "$(cat "$MOCK_LOG")" "restorecon"
}

test_configure_cache_enables_timer_offline_without_running_systemd() {
    CACHE_DIR="$TEST_TEMP_DIR/cache"
    mkdir -p "$TEST_TEMP_DIR/systemd"
    systemd_running_exit_code=1

    configure_cache "$TEST_TEMP_DIR" "$TEST_TEMP_DIR/systemd" >/dev/null
    result=$?

    assertEquals "Expected to return 0 without a running systemd" 0 "$result"
    assertContains "Expected the timer enabled for the next boot" "$(cat "$MOCK_LOG")" "systemctl enable opkssh-cache-clean.timer"
    assertNotContains "Expected no daemon-reload" "$(cat "$MOCK_LOG")" "daemon-reload"
    assertNotContains "Expected no --now" "$(cat "$MOCK_LOG")" "--now"
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
