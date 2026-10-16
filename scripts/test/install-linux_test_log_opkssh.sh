#!/bin/bash

export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

TEST_TEMP_DIR=""

setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    OPKSSH_LOGFILE="$TEST_TEMP_DIR/opkssh.log"
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    # shellcheck disable=SC2034 # read by log_opkssh_installation
    DEFAULT_PROVIDERS_WRITTEN=false
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

date() {
    echo "Wed Jun  4 21:59:26 PM CEST 2025"
}

# Tests

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
    export BINARY_NAME="opkssh"
    export INSTALL_DIR="$TEST_TEMP_DIR"

    output=$(log_opkssh_installation "$OPKSSH_LOGFILE")
    result=$?

    readarray -t mock_log < "$MOCK_LOG"
    readarray -t log_file < "$OPKSSH_LOGFILE"

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertEquals "Expected output to print installation success on stdout" "Installation successful! Run 'opkssh' to use it." "$output"
    assertContains "Expected to set correct permission on log file" "${mock_log[*]}" "chmod 660 $OPKSSH_LOGFILE"
    assertContains "Expected to set correct ownership on log file" "${mock_log[*]}" "chown root:$AUTH_CMD_USER $OPKSSH_LOGFILE"
    assertEquals "Expected to log correct information" "Successfully installed $BINARY_NAME (INSTALLED_ON: Wed Jun  4 21:59:26 PM CEST 2025, VERSION_INSTALLED: opkssh version X.Y.Z, INSTALL_VERSION: $INSTALL_VERSION, LOCAL_INSTALL_FILE: , HOME_POLICY: true, RESTART_SSH: true)" "${log_file[1]}"

}

test_log_opkssh_installation_default_providers_notice() {
    # Create dummy opkssh binary
    cat <<'EOF' >> "$TEST_TEMP_DIR/opkssh"
#!/bin/bash
if [[ "$1" == "--version" ]]; then
    echo "opkssh version X.Y.Z"
fi
EOF
    /usr/bin/chmod +x "$TEST_TEMP_DIR/opkssh"
    export BINARY_NAME="opkssh"
    export INSTALL_DIR="$TEST_TEMP_DIR"
    # shellcheck disable=SC2034 # read by log_opkssh_installation
    DEFAULT_PROVIDERS_WRITTEN=true

    output=$(log_opkssh_installation "$OPKSSH_LOGFILE")
    result=$?
    readarray -t output_lines <<< "$output"

    assertEquals "Expected to return 0 on success" 0 "$result"
    assertEquals "Expected output to print installation success first" "Installation successful! Run 'opkssh' to use it." "${output_lines[0]}"
    assertEquals "Expected output to end with the default providers notice" "Note: $DEFAULT_PROVIDERS_NOTICE" "${output_lines[2]}"
    assertContains "Expected the notice to mention opkssh audit" "$output" "'opkssh audit'"
}

# shellcheck disable=SC1091
source shunit2
