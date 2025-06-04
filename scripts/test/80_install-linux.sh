#!/bin/bash

export SHUNIT_RUNNIN=1

echo "Running tests: ${0##*/}"

# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""

setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    RESTART_SSH=true
    OS_TYPE=""
    HOME_POLICY=true
    SUDOERS_PATH="$TEST_TEMP_DIR/sudo"
    OPKSSH_LOGFILE="$TEST_TEMP_DIR/opkssh.log"
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    export SUDOERS_PATH HOME_POLICY
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

systemctl() {
    echo "systemctl $*" >> "$MOCK_LOG"
}

date() {
    echo "Wed Jun  4 21:59:26 PM CEST 2025"
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

test_restart_openssh_server_no_restart() {
    export RESTART_SSH=false

    output=$(restart_openssh_server)
    result=$?

    assertEquals "Expected result 0 on success" 0 "$result"
    assertContains "Expected output to inform about skipping openSSH server restart" "$output" "skipping SSH restart"
    assertTrue "Expected that systemctl isn't called" "[ ! -f \"$TEST_TEMP_DIR/mock.log\" ]"
}

test_restart_openssh_server_redhat() {
    export OS_TYPE="redhat"
    output=$(restart_openssh_server)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertEquals "Expected systemctl to have correct parameters" "systemctl restart sshd" "${mock_log[0]}"
    assertEquals "Expected only one command to be called" 1 "${#mock_log[@]}"
}

test_restart_openssh_server_suse() {
    export OS_TYPE="suse"
    output=$(restart_openssh_server)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertEquals "Expected systemctl to have correct parameters" "systemctl restart sshd" "${mock_log[0]}"
    assertEquals "Expected only one command to be called" 1 "${#mock_log[@]}"
}


test_restart_openssh_server_debian() {
    export OS_TYPE="debian"
    output=$(restart_openssh_server)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertEquals "Expected systemctl to have correct parameters" "systemctl restart ssh" "${mock_log[0]}"
    assertEquals "Expected only one command to be called" 1 "${#mock_log[@]}"
}

test_restart_openssh_server_arch() {
    export OS_TYPE="arch"
    output=$(restart_openssh_server)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    assertEquals "Expected output to be empty" "" "$output"
    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertEquals "Expected systemctl to have correct parameters" "systemctl restart sshd" "${mock_log[0]}"
    assertEquals "Expected only one command to be called" 1 "${#mock_log[@]}"
}

test_restart_openssh_server_unsupported_os() {
    export OS_TYPE="FooBar"
    output=$(restart_openssh_server)
    result=$?

    assertEquals "Expected result to be 1 on failure" 1 "$result"
    assertTrue "Expected that systemctl isn't called" "[ ! -f \"$TEST_TEMP_DIR/mock.log\" ]"
    assertContains "Expected to inform about unsupported OS" "$output" "$output"

}

test_configure_sudo_no_existing_file() {
    output=$(configure_sudo)
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    readarray -t sudo_content < "$SUDOERS_PATH"

    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertContains "Expected output to inform about creating sudo file" "$output" "Creating sudoers file at"
    assertContains "Expected output to contain information about adding sudo rule" "$output" "Adding sudoers rule for"
    assertTrue "Expected sudo file to be created" "[ -f \"$SUDOERS_PATH\" ]"
    assertContains "Excepcted sudo file to be configured with correct permissions" "chmod 440 $SUDOERS_PATH" "${mock_log[*]}"
    assertEquals "Expected sudo rule to be configured correctly" "${sudo_content[1]}" "opksshuser ALL=(ALL) NOPASSWD: /usr/local/bin/opkssh readhome *"
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
    assertContains "Expected sudo rule to be configured correctly" "${sudo_content[*]}" "opksshuser ALL=(ALL) NOPASSWD: /usr/local/bin/opkssh readhome *"
    assertEquals "Expected sudo file to contain three rows" 3 "${#sudo_content[@]}"
}

test_configure_sudo_existing_file_with_opkssh_entry() {
    echo "opksshuser ALL=(ALL) NOPASSWD: /usr/local/bin/opkssh readhome *" >> "$SUDOERS_PATH"
    output=$(configure_sudo)
    result=$?

    readarray -t sudo_content < "$SUDOERS_PATH"

    assertEquals "Expected result to be 0 on success" 0 "$result"
    assertContains "Expected output to be empty" "" "$output"
    assertTrue "Expected sudo file to exist" "[ -f \"$SUDOERS_PATH\" ]"
    assertContains "Expected sudo rule to be configured correctly" "opksshuser ALL=(ALL) NOPASSWD: /usr/local/bin/opkssh readhome *" "${sudo_content[0]}"
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

test_log_opkssh_installation() {
    # Create dummy opkssh binary
    cat <<'EOF' >> "$TEST_TEMP_DIR/opkssh"
#!/bin/bash
if [[ "$1" == "--version" ]]; then
    echo "opkssh version X.Y.Z"
fi
EOF
    /usr/bin/chmod +x "$TEST_TEMP_DIR/opkssh"
    # Add a dummy line in the log file
    echo "This is just a dummy line" > "$OPKSSH_LOGFILE"

    export INSTALL_DIR="$TEST_TEMP_DIR"

    output=$(log_opkssh_installation "$OPKSSH_LOGFILE")
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    readarray -t log_file < "$OPKSSH_LOGFILE"

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertEquals "Expected output to print installation success on stdout" "Installation successful! Run 'opkssh' to use it." "$output"
    assertContains "Expected to set correct permission on log file" "${mock_log[*]}" "chmod 660 $OPKSSH_LOGFILE"
    assertContains "Expected to set correct ownership on log file" "${mock_log[*]}" "chown root:opksshuser $OPKSSH_LOGFILE"
    assertEquals "Expected to log correct information" "Successfully installed opkssh (INSTALLED_ON: Wed Jun  4 21:59:26 PM CEST 2025, VERSION_INSTALLED: opkssh version X.Y.Z, INSTALL_VERSION: latest, LOCAL_INSTALL_FILE: , HOME_POLICY: true, RESTART_SSH: true)" "${log_file[1]}"

}
# shellcheck disable=SC1091
source shunit2
