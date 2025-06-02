#!/bin/bash
export SHUNIT_RUNNIN=1

echo "Running tests: ${0##*/}"

# Source install-linux.sh
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

setUp() {
    mock_log=()
    mock_command_found=true
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    INSTALL_DIR="$TEST_TEMP_DIR/install"
    mkdir -p "$INSTALL_DIR"
    # Default values
    INSTALL_VERSION="latest"
    LOCAL_INSTALL_FILE=""
    CPU_ARCH="amd64"
    export CPU_ARCH INSTALL_DIR INSTALL_VERSION LOCAL_INSTALL_FILE
}

tearDown() {
    rm -rf "$TEST_TEMP_DIR"
}

# Mock functions
command() {
    if [[ "$1" == "-v" && "$2" == "$INSTALL_DIR/$BINARY_NAME" ]]; then
        $mock_command_found && return 0 || return 1
    fi
    builtin command "$@"
}

wget() {
    printf "#!/bin/bash\necho Mock opkssh binary from wget\n" > "$4"  # Simulate binary
}

mv() {
    mock_log+=("mv $*")
    cp "$1" "$2"
    rm "$1"
}

chmod() {
    mock_log+=("chmod $*")
    /usr/bin/chmod "$@"
}

chown() {
    mock_log+=("chown $*")
}

# Running tests

test_install_opkssh_binary_from_local_file_success() {
    LOCAL_INSTALL_FILE="$TEST_TEMP_DIR/mock_local_opkssh"
    printf "#!/bin/bash\necho local mock\n" > "$LOCAL_INSTALL_FILE"
    chmod +x "$LOCAL_INSTALL_FILE"
    export LOCAL_INSTALL_FILE

    output=$(install_opkssh_binary 2>&1)
    result=$?

    assertEquals "Expected to return 0 on success" 0  "$result"
    assertContains "$output" "Using binary from specified path"
    assertTrue "Binary should exist in install dir" "[ -f \"$INSTALL_DIR/$BINARY_NAME\" ]"
}

test_install_opkssh_binary_from_local_file_missing() {
    LOCAL_INSTALL_FILE="$TEST_TEMP_DIR/does_not_exist"

    output=$(install_opkssh_binary 2>&1)
    result=$?

    assertEquals "Expected to return 1 on failure" 1 "$result"
    assertContains "Expected error message" "$output" "Error: Specified binary path does not exist"
}

test_install_opkssh_binary_from_remote_latest() {
    LOCAL_INSTALL_FILE=""
    INSTALL_VERSION="latest"

    output=$(install_opkssh_binary 2>&1)
    result=$?

    assertEquals "Expected success for latest install" 0 "$result"
    assertContains "$output" "Downloading version latest of opkssh from https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-amd64"
    assertTrue "Binary should be installed" "[ -x \"$INSTALL_DIR/$BINARY_NAME\" ]"
}

test_install_opkssh_binary_from_remote_specific_version() {
    LOCAL_INSTALL_FILE=""
    INSTALL_VERSION="v1.2.3"

    output=$(install_opkssh_binary 2>&1)
    result=$?

    assertEquals "Expected success for latest install" 0 "$result"
    assertContains "$output" "Downloading version v1.2.3 of opkssh from https://github.com/openpubkey/opkssh/releases/download/v1.2.3/opkssh-linux-amd64"
    assertTrue "Binary should be installed" "[ -x \"$INSTALL_DIR/$BINARY_NAME\" ]"
}

test_install_opkssh_binary_command_not_found_after_install() {
    mock_command_found=false

    output=$(install_opkssh_binary 2>&1)
    result=$?

    assertEquals "Expected failure if command not found" 1 "$result"
    assertContains "$output" "Installation failed"
}

source shunit2
