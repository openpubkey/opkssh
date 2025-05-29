#!/bin/bash
export SHUNIT_RUNNIN=1

# Source install-linux.sh
source install-linux.sh

#
# Override functions for mocking
#
file_exists() {
    [[ " ${mock_files[*]} " == *" $1 "* ]]
}

grep_suse() {
    [[ "$mock_grep_content" == *"ID_LIKE=suse"* ]]
}

get_uname_arch() {
    echo "$mock_uname_arch"
}


# Running tests

test_global_variables() {
    assertEquals "AUTH_CMD_USER should be set to 'opksshuser'" "opksshuser" "$AUTH_CMD_USER"
    assertEquals "AUTH_CMD_GROUP should be set to 'opksshuser'" "opksshuser" "$AUTH_CMD_GROUP"
    assertEquals "SUDOERS_PATH should be set to '/etc/sudoers.d/opkssh'" "/etc/sudoers.d/opkssh" "$SUDOERS_PATH"
    assertEquals "HOME_POLICY should default to 'true'" "true" "$HOME_POLICY"
    assertEquals "RESTART_SSH should default to 'true'" "true" "$RESTART_SSH"
    assertEquals "OVERWRITE_ACTIVE_CONFIG should default to 'false'" "false" "$OVERWRITE_ACTIVE_CONFIG"
    assertEquals "LOCAL_INSTALL_FILE should default to empty string" "" "$LOCAL_INSTALL_FILE"
    assertEquals "INSTALL_VERSION should default to 'latest'" "latest" "$INSTALL_VERSION"
    assertEquals "INSTALL_DIR should default to '/usr/local/bin'" "/usr/local/bin" "$INSTALL_DIR"
    assertEquals "BINARY_NAME should be 'opkssh'" "opkssh" "$BINARY_NAME"
    assertEquals "GITHUB_REPO should be 'openpubkey/opkssh'" "openpubkey/opkssh" "$GITHUB_REPO"
    assertEquals "OS_TYPE should default to empty string" "" "$OS_TYPE"
    assertEquals "CPU_ARCH should default to empty string" "" "$CPU_ARCH"
}

test_check_bash_version_4_1() {
    output=$(check_bash_version 4 1)
    result=$?
    assertEquals "Expected check_bash_version to return success (0) for version 4.1" 0 $result
    assertContains "Expected output to include '4.1' when checking bash version 4.1" "$output" "4.1"
}

test_check_bash_version_3_2() {
    output=$(check_bash_version 3 2)
    result=$?
    assertEquals "Expected check_bash_version to return success (0) for version 3.2" 0 $result
    assertContains "Expected output to include '4.1' when checking bash version 3.2" "$output" "3.2"
}

test_check_bash_version_3_1_2() {
    output=$(check_bash_version 3 1 2>&1)
    result=$?
    assertEquals "Expected check_bash_version to return failure (1) for unsupported version 3.1.2" 1 $result
    assertContains "Expected error message to mention 'Unsupported Bash version'" "$output" "Unsupported Bash version"
}

test_determine_linux_type_redhat() {
    mock_files=("/etc/redhat-release")
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return success (0) for /etc/redhat-release" 0 $result
    assertEquals "Expected the output to equal 'redhat' for /etc/redhat-release" "redhat" "$output"
}

test_determine_linux_type_debian() {
    mock_files=("/etc/debian_version")
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return success (0) for /etc/debian_version" 0 $result
    assertEquals "Expected the output to equal 'debian' for /etc/debian_version" "debian" "$output"
}

test_determine_linux_type_arch() {
    mock_files=("/etc/arch-release")
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return success (0) for /etc/arch-release" 0 $result
    assertEquals "Expected the output to equal 'arch' for /etc/arch-release" "arch" "$output"
}

test_determine_linux_type_suse() {
    mock_files=("/etc/os-release")
    mock_grep_content="ID_LIKE=suse"
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return success (0) for /etc/os-release and greping 'ID_LIKE=suse'" 0 $result
    assertEquals "Expected the output to equal 'suse' for /etc/os-release" "suse" "$output"
}

test_determine_linux_type_os_release_non_suse() {
    mock_files=("/etc/os-release")
    mock_grep_content="ID_LIKE=ubuntu"
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return failure (1) for /etc/os-release and greping 'ID_LIKE=ubuntu'" 1 $result
    assertEquals "Expected the output to equal 'Unsupported OS type.' for /etc/os-release greping 'ID_LIKE=ubuntu" "Unsupported OS type." "$output"
}

test_determine_linux_type_unsupported_os() {
    mock_files=()
    mock_grep_content=""
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return failure (1) for unknown file" 1 $result
    assertEquals "Expected the output to equal 'Unsupported OS type.' for unknonw file" "Unsupported OS type." "$output"
}

test_check_cpu_architecture_x86_64() {
    mock_uname_arch="x86_64"
    output=$(check_cpu_architecture)
    result=$?
    assertEquals "Expected check_cpu_architecture to return success (0) for x86_64 architecture" 0 $result
    assertEquals "Expected check_cpu_architecture to equal 'amd64' for x86_64 architecture" "amd64" "$output"
}

test_check_cpu_architecture_aarch64() {
    mock_uname_arch="aarch64"
    output=$(check_cpu_architecture)
    result=$?
    assertEquals "Expected check_cpu_architecture to return success (0) for aarch64 architecture" 0 $result
    assertEquals "Expected check_cpu_architecture to equal 'arm64' for x86_64 architecture" "arm64" "$output"
}

test_check_cpu_architecture_amd64() {
    mock_uname_arch="amd64"
    output=$(check_cpu_architecture)
    result=$?
    assertEquals "Expected check_cpu_architecture to return success (0) for amd64 architecture" 0 $result
    assertEquals "Expected check_cpu_architecture to equal 'amd64' for amd64 architecture" "amd64" "$output"
}

test_check_cpu_architecture_arm64() {
    mock_uname_arch="arm64"
    output=$(check_cpu_architecture)
    result=$?
    assertEquals "Expected check_cpu_architecture to return success (0) for arm64 architecture" 0 $result
    assertEquals "Expected check_cpu_architecture to equal 'arm64' for arm64 architecture" "arm64" "$output"
}

test_check_cpu_architecture_foobar() {
    mock_uname_arch="foobar"
    output=$(check_cpu_architecture 2>&1)
    result=$?
    assertEquals "Expected check_cpu_architecture to return failure (1) for foobar architecture" 1 $result
    assertContains "Expected check_cpu_architecture to contain 'Unsupported' for foobar architecture" "$output" "Unsupported"
}

test_running_as_root_uid_0() {
    output=$(running_as_root 0)
    result=$?
    assertEquals "Expected running_as_root to return success (0) for UID 0" 0 $?
    assertEquals "Expected running_as_root output to be empty '' for UID 0" "" "$output"
}

test_running_as_root_uid_1000() {
    output=$(running_as_root 1000 2>&1)
    result=$?
    assertEquals "Expected running_as_root to return failure (1) for UID 1000" 1 $result
    assertContains "Expected running_as_root to contain 'This script must be run as root' for UID 1000" "$output" "This script must be run as root"
}

source shunit2
