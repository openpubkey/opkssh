#!/bin/bash

export SHUNIT_RUNNIN=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""
SSHD_CONFIG=""
SSHD_CONFIG_D=""

setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    mkdir -p "$TEST_TEMP_DIR/sshd_config.d"
    SSHD_CONFIG="$TEST_TEMP_DIR/sshd_config"
    SSHD_CONFIG_D="$TEST_TEMP_DIR/sshd_config.d"
    OVERWRITE_ACTIVE_CONFIG=false
    export OVERWRITE_ACTIVE_CONFIG
}

tearDown() {
    /usr/bin/rm -rf "$TEST_TEMP_DIR"
}

# Tests
test_configure_openssh_server_no_existing_config() {
    configure_openssh_server "$TEST_TEMP_DIR"
    result=$?

    assertEquals "Expected return value to be 0" 0 "$result"
    assertTrue "/etc/ssh/sshd_config.d/60-opk-ssh.conf should not be createad" "[ -f \"$SSHD_CONFIG_D\"/60-opk-ssh.conf ]"

    readarray -t conf_file < "$SSHD_CONFIG_D/60-opk-ssh.conf"
    assertEquals "Expected AuthorizedKeysCommand to be configured correctly" "AuthorizedKeysCommand ${INSTALL_DIR}/${BINARY_NAME} verify %u %k %t" "${conf_file[0]}"
    assertEquals "Expected AuthorizedKeysCommandUser to be configured correctly" "AuthorizedKeysCommandUser $AUTH_CMD_USER" "${conf_file[1]}"
}


test_configure_openssh_server_sshd_config_no_include_with_no_directives() {
    echo "FooConfigLine bar" >> "$SSHD_CONFIG"
    echo "BarConfigLine foo" >> "$SSHD_CONFIG"

    configure_openssh_server "$TEST_TEMP_DIR"
    result=$?
    readarray -t conf_file < "$SSHD_CONFIG"

    assertEquals "Expected return value to be 0" 0 "$result"
    assertTrue "sshd_config.d/60-opk-ssh.conf should not be created" "[ ! -f \"$SSHD_CONFIG_D/60-opk-ssh.conf\" ]"
    assertContains "Expected new AuthorizedKeysCommand to be added" "${conf_file[*]}" "AuthorizedKeysCommand ${INSTALL_DIR}/${BINARY_NAME} verify %u %k %t"
    assertContains "Expected new AuthorizedKeysCommandUser to be added" "${conf_file[*]}" "AuthorizedKeysCommandUser $AUTH_CMD_USER"
}

test_configure_openssh_server_sshd_config_no_include_with_directive() {
    echo "AuthorizedKeysCommand /bin/foo" >> "$SSHD_CONFIG"
    echo "AuthorizedKeysCommandUser foo" >> "$SSHD_CONFIG"

    configure_openssh_server "$TEST_TEMP_DIR"
    result=$?
    readarray -t conf_file < "$SSHD_CONFIG"

    assertEquals "Expected return value to be 0" 0 "$result"
    assertTrue "sshd_config.d/60-opk-ssh.conf should not be created" "[ ! -f \"$SSHD_CONFIG_D/60-opk-ssh.conf\" ]"
    assertContains "Expected existing AuthorizedKeysCommand to be commented out" "${conf_file[*]}" "#AuthorizedKeysCommand /bin/foo"
    assertContains "Expected existing AuthorizedKeysCommandUser to be commented out" "${conf_file[*]}" "#AuthorizedKeysCommandUser foo"
    assertContains "Expected new AuthorizedKeysCommand to be added" "${conf_file[*]}" "AuthorizedKeysCommand ${INSTALL_DIR}/${BINARY_NAME} verify %u %k %t"
    assertContains "Expected new AuthorizedKeysCommandUser to be added" "${conf_file[*]}" "AuthorizedKeysCommandUser $AUTH_CMD_USER"
}

test_configure_openssh_server_sshd_config_with_include_no_directive(){
    {
        echo "Include /etc/ssh/sshd_config.d/*.conf"
        echo "FooConfigLine bar"
        echo "BarConfigLine foo"
    } >> "$SSHD_CONFIG"

    configure_openssh_server "$TEST_TEMP_DIR"
    result=$?
    readarray -t conf_file < "$SSHD_CONFIG_D/60-opk-ssh.conf"

    assertEquals "Expected return value to be 0" 0 "$result"
    assertTrue "Expected sshd_config.d/60-opk-ssh.conf file to be created" "[ -f \"$SSHD_CONFIG_D/60-opk-ssh.conf\" ]"
    assertEquals "Expected AuthorizedKeysCommand to be configured correctly" "AuthorizedKeysCommand ${INSTALL_DIR}/${BINARY_NAME} verify %u %k %t" "${conf_file[0]}"
    assertEquals "Expected AuthorizedKeysCommandUser to be configured correctly" "AuthorizedKeysCommandUser $AUTH_CMD_USER" "${conf_file[1]}"
}

test_configure_openssh_server_sshd_config_with_include_with_directive(){
    {
        echo "Include /etc/ssh/sshd_config.d/*.conf"
        echo "FooConfigLine bar"
        echo "BarConfigLine foo"
        echo "AuthorizedKeysCommand /bin/foo"
        echo "AuthorizedKeysCommandUser foo"
    } >> "$SSHD_CONFIG"

    configure_openssh_server "$TEST_TEMP_DIR"
    result=$?
    readarray -t conf_file < "$SSHD_CONFIG_D/60-opk-ssh.conf"

    assertEquals "Expected return value to be 0" 0 "$result"
    assertTrue "Expected sshd_config.d/60-opk-ssh.conf file to be created" "[ -f \"$SSHD_CONFIG_D/60-opk-ssh.conf\" ]"
    assertEquals "Expected AuthorizedKeysCommand to be configured correctly" "AuthorizedKeysCommand ${INSTALL_DIR}/${BINARY_NAME} verify %u %k %t" "${conf_file[0]}"
    assertEquals "Expected AuthorizedKeysCommandUser to be configured correctly" "AuthorizedKeysCommandUser $AUTH_CMD_USER" "${conf_file[1]}"
}

test_configure_openssh_server_existing_sshd_d_no_overwrite() {
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$SSHD_CONFIG"
    {
        echo "FooConfigLine bar"
        echo "BarConfigLine foo"
        echo "AuthorizedKeysCommand /bin/foo"
        echo "AuthorizedKeysCommandUser foo"
    } >> "$SSHD_CONFIG_D/50-foo.conf"

    configure_openssh_server "$TEST_TEMP_DIR"
    result=$?

    assertEquals "Expected return value to be 0" 0 "$result"
    readarray -t original_conf < "$SSHD_CONFIG_D/50-foo.conf"
    assertTrue "Expected sshd_config.d/49-opk-ssh.conf file to be created" "[ -f \"$SSHD_CONFIG_D/49-opk-ssh.conf\" ]"
    readarray -t new_conf < "$SSHD_CONFIG_D/49-opk-ssh.conf"
    assertTrue "Expected original config file sshd_config.d/50-foo.conf to be untuched" "[ \"${#original_conf[@]}\" -eq \"4\" ]"
    assertEquals "Expected AuthorizedKeysCommand to be configured correctly" "AuthorizedKeysCommand ${INSTALL_DIR}/${BINARY_NAME} verify %u %k %t" "${new_conf[0]}"
    assertEquals "Expected AuthorizedKeysCommandUser to be configured correctly"  "AuthorizedKeysCommandUser $AUTH_CMD_USER"  "${new_conf[1]}"
}

test_configure_openssh_server_existing_sshd_d_with_overwrite() {
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$SSHD_CONFIG"
    {
        echo "FooConfigLine bar"
        echo "BarConfigLine foo"
        echo "AuthorizedKeysCommand /bin/foo"
        echo "AuthorizedKeysCommandUser foo"
    } >> "$SSHD_CONFIG_D/50-foo.conf"
    OVERWRITE_ACTIVE_CONFIG=true

    configure_openssh_server "$TEST_TEMP_DIR"
    result=$?

    assertEquals "Expected return value to be 0" 0 "$result"
    readarray -t original_conf < "$SSHD_CONFIG_D/50-foo.conf"
    assertTrue "Expected sshd_config.d/49-opk-ssh.conf file not to be created" "[ ! -f \"$SSHD_CONFIG_D/49-opk-ssh.conf\" ]"
    assertEquals "Expected the original config to be commented out" "#AuthorizedKeysCommand /bin/foo" "${original_conf[2]}"
    assertEquals "Expected the original config to be commented out" "#AuthorizedKeysCommandUser foo" "${original_conf[3]}"
    assertEquals "Expected AuthorizedKeysCommand to be configured" "AuthorizedKeysCommand ${INSTALL_DIR}/${BINARY_NAME} verify %u %k %t" "${original_conf[4]}"
    assertEquals "Expected AuthorizedKeysCommandUser to be configured" "AuthorizedKeysCommandUser $AUTH_CMD_USER" "${original_conf[5]}"
}

test_configure_openssh_server_existing_sshd_d_no_overwrite_00_config() {
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$SSHD_CONFIG"
    {
        echo "FooConfigLine bar"
        echo "BarConfigLine foo"
        echo "AuthorizedKeysCommand /bin/foo"
        echo "AuthorizedKeysCommandUser foo"
    } >> "$SSHD_CONFIG_D/00-foo.conf"

    output=$(configure_openssh_server "$TEST_TEMP_DIR" 2>&1)
    result=$?

    assertEquals "Expected return value to be 1 when failing to create config" 1 "$result"
    readarray -t original_conf < "$SSHD_CONFIG_D/00-foo.conf"
    assertTrue "Expected original config file sshd_config.d/00-foo.conf to be untuched" "[ \"${#original_conf[@]}\" -eq \"4\" ]"
    assertEquals "Expected original config file sshd_config.d/00-foo.conf to be untuched" "FooConfigLine bar" "${original_conf[0]}"
    assertEquals "Expected original config file sshd_config.d/00-foo.conf to be untuched" "BarConfigLine foo" "${original_conf[1]}"
    assertEquals "Expected original config file sshd_config.d/00-foo.conf to be untuched" "AuthorizedKeysCommand /bin/foo" "${original_conf[2]}"
    assertEquals "Expected original config file sshd_config.d/00-foo.conf to be untuched" "AuthorizedKeysCommandUser foo" "${original_conf[3]}"
    assertContains "Expected output to contain reason on failure" "$output" "Cannot create configuration with higher priority"
}

# shellcheck disable=SC1091
source shunit2
