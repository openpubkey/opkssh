#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

setUp() {
    mock_command_found=true
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    INSTALL_DIR="$TEST_TEMP_DIR/install"
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    mkdir -p "$INSTALL_DIR"
    # Default values
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
    echo "wget $*" >> "$MOCK_LOG"
    printf "#!/bin/bash\necho Mock opkssh binary from wget\n" > "$4"  # Simulate binary
}

mv() {
    echo "mv $*" >> "$MOCK_LOG"
    cp "$1" "$2"
    rm "$1"
}

chmod() {
    echo "chmod $*" >> "$MOCK_LOG"
    /usr/bin/chmod "$@"
}

chown() {
    echo "chown $*" >> "$MOCK_LOG"
}

# Running tests

test_install_opkssh_binary_from_local_file_success() {
    LOCAL_INSTALL_FILE="$TEST_TEMP_DIR/mock_local_opkssh"
    printf "#!/bin/bash\necho local mock\n" > "$LOCAL_INSTALL_FILE"
    export LOCAL_INSTALL_FILE

    output=$(install_opkssh_binary 2>&1)
    result=$?
    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected to return 0 on success" 0  "$result"
    assertContains "$output" "Using binary from specified path"
    assertTrue "Binary should exist in install dir" "[ -f \"$INSTALL_DIR/$BINARY_NAME\" ]"
    assertEquals "Expected to move local install file to binary path" \
        "mv $TEST_TEMP_DIR/mock_local_opkssh $INSTALL_DIR/$BINARY_NAME" "${mock_log[0]}"
    assertEquals "Expected to set execution flag on opkssh binary" \
        "chmod +x $INSTALL_DIR/$BINARY_NAME" "${mock_log[1]}"
    assertEquals "Expected to set root as owner and AUTH_CMD_GROUP ownership on binary" \
        "chown root:$AUTH_CMD_GROUP $INSTALL_DIR/$BINARY_NAME" "${mock_log[2]}"
    assertEquals "Expected to set correct file mode bits on opkssh binary" \
        "chmod 755 $INSTALL_DIR/$BINARY_NAME" "${mock_log[3]}"

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
    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected success for default version install" 0 "$result"
    assertContains "Expected Download message to output when downloading" \
        "$output" "Downloading version $INSTALL_VERSION of $BINARY_NAME from https://github.com/${GITHUB_REPO}/releases/$INSTALL_VERSION/download/opkssh-linux-amd64"
    assertTrue "Binary should be installed" "[ -x \"$INSTALL_DIR/$BINARY_NAME\" ]"
    assertEquals "Expected wget to be called with correct parameters" \
        "wget -q --show-progress -O $BINARY_NAME https://github.com/${GITHUB_REPO}/releases/$INSTALL_VERSION/download/opkssh-linux-${CPU_ARCH}" "${mock_log[0]}"
    assertEquals "Expected to move downloaded install file to binary path" \
        "mv $BINARY_NAME $INSTALL_DIR/$BINARY_NAME" "${mock_log[1]}"
    assertEquals "Expected to set execution flag on opkssh binary" \
        "chmod +x $INSTALL_DIR/$BINARY_NAME" "${mock_log[2]}"
    assertEquals "Expected to set root as owner and AUTH_CMD_GROUP ownership on binary" \
        "chown root:$AUTH_CMD_GROUP $INSTALL_DIR/$BINARY_NAME" "${mock_log[3]}"
    assertEquals "Expected to set correct file mode bits on opkssh binary" \
        "chmod 755 $INSTALL_DIR/$BINARY_NAME" "${mock_log[4]}"
}

test_install_opkssh_binary_from_remote_specific_version() {
    LOCAL_INSTALL_FILE=""
    INSTALL_VERSION="v1.2.3"

    output=$(install_opkssh_binary 2>&1)
    result=$?
    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected success for v.1.2.3 install" 0 "$result"
    assertContains "Expected Download message when downloading" \
        "$output" "Downloading version v1.2.3 of $BINARY_NAME from https://github.com/${GITHUB_REPO}/releases/download/v1.2.3/opkssh-linux-amd64"
    assertTrue "Binary should be installed" "[ -x \"$INSTALL_DIR/$BINARY_NAME\" ]"
    assertEquals "Expected wget to be called with correct parameters" \
        "wget -q --show-progress -O $BINARY_NAME https://github.com/${GITHUB_REPO}/releases/download/v1.2.3/opkssh-linux-${CPU_ARCH}" "${mock_log[0]}"
    assertEquals "Expected to move downloaded install file to binary path" \
        "mv $BINARY_NAME $INSTALL_DIR/$BINARY_NAME" "${mock_log[1]}"
    assertEquals "Expected to set execution flag on opkssh binary" \
        "chmod +x $INSTALL_DIR/$BINARY_NAME" "${mock_log[2]}"
    assertEquals "Expected to set root as owner and AUTH_CMD_GROUP ownership on binary" \
        "chown root:$AUTH_CMD_GROUP $INSTALL_DIR/$BINARY_NAME" "${mock_log[3]}"
    assertEquals "Expected to set correct file mode bits on opkssh binary" \
        "chmod 755 $INSTALL_DIR/$BINARY_NAME" "${mock_log[4]}"
}

test_install_opkssh_binary_command_not_found_after_install() {
    mock_command_found=false

    output=$(install_opkssh_binary 2>&1)
    result=$?

    assertEquals "Expected failure if command not found" 1 "$result"
    assertContains "$output" "Installation failed"
}

# shellcheck disable=SC1091
source shunit2
