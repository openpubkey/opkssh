#!/bin/bash
export SHUNIT_RUNNING=1

test_global_variables() {
    # Unset all related env vars to test default behavior
    unset OPKSSH_INSTALL_AUTH_CMD_USER
    unset OPKSSH_INSTALL_AUTH_CMD_GROUP
    unset OPKSSH_INSTALL_SUDOERS_PATH
    unset OPKSSH_INSTALL_HOME_POLICY
    unset OPKSSH_INSTALL_RESTART_SSH
    unset OPKSSH_INSTALL_OVERWRITE_ACTIVE_CONFIG
    unset OPKSSH_INSTALL_LOCAL_INSTALL_FILE
    unset OPKSSH_INSTALL_VERSION
    unset OPKSSH_INSTALL_DIR
    unset OPKSSH_INSTALL_BINARY_NAME
    unset OPKSSH_INSTALL_GITHUB_REPO

    # Source the script again to reinitialize variables
    # shellcheck disable=SC1091
    source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

    assertEquals "Default AUTH_CMD_USER should be 'opksshuser'" "opksshuser" "$AUTH_CMD_USER"
    assertEquals "Default AUTH_CMD_GROUP should be 'opksshuser'" "opksshuser" "$AUTH_CMD_GROUP"
    assertEquals "Default SUDOERS_PATH should be '/etc/sudoers.d/opkssh'" "/etc/sudoers.d/opkssh" "$SUDOERS_PATH"
    assertEquals "Default HOME_POLICY should be 'true'" "true" "$HOME_POLICY"
    assertEquals "Default RESTART_SSH should be 'true'" "true" "$RESTART_SSH"
    assertEquals "Default OVERWRITE_ACTIVE_CONFIG should be 'false'" "false" "$OVERWRITE_ACTIVE_CONFIG"
    assertEquals "Default LOCAL_INSTALL_FILE should be empty" "" "$LOCAL_INSTALL_FILE"
    assertEquals "Default INSTALL_VERSION should be 'latest'" "latest" "$INSTALL_VERSION"
    assertEquals "Default INSTALL_DIR should be '/usr/local/bin'" "/usr/local/bin" "$INSTALL_DIR"
    assertEquals "Default BINARY_NAME should be 'opkssh'" "opkssh" "$BINARY_NAME"
    assertEquals "Default GITHUB_REPO should be 'openpubkey/opkssh'" "openpubkey/opkssh" "$GITHUB_REPO"
    assertEquals "OS_TYPE should default to empty string" "" "$OS_TYPE"
    assertEquals "CPU_ARCH should default to empty string" "" "$CPU_ARCH"
}

test_global_variables_env_override() {
    export OPKSSH_INSTALL_AUTH_CMD_USER="testuser"
    export OPKSSH_INSTALL_AUTH_CMD_GROUP="testgroup"
    export OPKSSH_INSTALL_SUDOERS_PATH="/tmp/sudoers"
    export OPKSSH_INSTALL_HOME_POLICY="false"
    export OPKSSH_INSTALL_RESTART_SSH="false"
    export OPKSSH_INSTALL_OVERWRITE_ACTIVE_CONFIG="true"
    export OPKSSH_INSTALL_LOCAL_INSTALL_FILE="/tmp/opkssh.tar.gz"
    export OPKSSH_INSTALL_VERSION="1.2.3"
    export OPKSSH_INSTALL_DIR="/opt/bin"
    export OPKSSH_INSTALL_BINARY_NAME="custom-opkssh"
    export OPKSSH_INSTALL_GITHUB_REPO="custom/repo"

    # Source the script again to reinitialize variables
    # shellcheck disable=SC1091
    source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

    assertEquals "AUTH_CMD_USER should be overridden to 'testuser'" "testuser" "$AUTH_CMD_USER"
    assertEquals "AUTH_CMD_GROUP should be overridden to 'testgroup'" "testgroup" "$AUTH_CMD_GROUP"
    assertEquals "SUDOERS_PATH should be overridden to '/tmp/sudoers'" "/tmp/sudoers" "$SUDOERS_PATH"
    assertEquals "HOME_POLICY should be overridden to 'false'" "false" "$HOME_POLICY"
    assertEquals "RESTART_SSH should be overridden to 'false'" "false" "$RESTART_SSH"
    assertEquals "OVERWRITE_ACTIVE_CONFIG should be overridden to 'true'" "true" "$OVERWRITE_ACTIVE_CONFIG"
    assertEquals "LOCAL_INSTALL_FILE should be overridden to '/tmp/opkssh.tar.gz'" "/tmp/opkssh.tar.gz" "$LOCAL_INSTALL_FILE"
    assertEquals "INSTALL_VERSION should be overridden to '1.2.3'" "1.2.3" "$INSTALL_VERSION"
    assertEquals "INSTALL_DIR should be overridden to '/opt/bin'" "/opt/bin" "$INSTALL_DIR"
    assertEquals "BINARY_NAME should be overridden to 'custom-opkssh'" "custom-opkssh" "$BINARY_NAME"
    assertEquals "GITHUB_REPO should be overridden to 'custom/repo'" "custom/repo" "$GITHUB_REPO"
    assertEquals "OS_TYPE should default to empty string" "" "$OS_TYPE"
    assertEquals "CPU_ARCH should default to empty string" "" "$CPU_ARCH"
}
# shellcheck disable=SC1091
source shunit2
