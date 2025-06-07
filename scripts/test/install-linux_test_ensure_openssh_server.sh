#!/bin/bash
export SHUNIT_RUNNIN=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

#
# Override functions for mocking
#
file_exists() {
    [[ " ${mock_files[*]} " == *" $1 "* ]]
}

dir_exists() {
    [[ " ${mock_dirs[*]} " == *" $1 "* ]]
}

rpm() {
    if [[ "$1" == "-q" && "$2" == "openssh-server" ]]; then
        return "$mock_rpm_result"
    fi
    return 1
}

dpkg() {
    if [[ "$1" == "-l" && "$mock_dpkg_result" -eq 0 ]]; then
        printf "ii  openssh-server           1:9.2p1-2+deb12u6      amd64\n"
        return 0
    else
        return 1
    fi
}

pacman() {
    if [[ "$1" == "-Q" && "$2" == "openssh" ]]; then
        return "$mock_pacman_result"
    fi
    return 1
}

# Running tests

test_ensure_openssh_server_installed_suse() {
    mock_files=("/etc/ssh/sshd_config")         # /etc/ssh/sshd_config present
    mock_dirs=("/etc/ssh/sshd_config.d")        # /etc/ssh/sshd_config.d present
    mock_rpm_result=0                           # Simulate rpm -q openssh-server success
    output=$(ensure_openssh_server suse 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 0 when installed on suse" 0 $result
    assertEquals "Expecded ensure_openssh_server output to be empty on success" "" "$output"
}

test_ensure_openssh_server_not_installed_suse() {
    mock_files=("/etc/ssh/sshd_config")         # /etc/ssh/sshd_config present
    mock_dirs=("/etc/ssh/sshd_config.d")        # /etc/ssh/sshd_config.d present
    mock_rpm_result=1                           # Simulate rpm -q openssh-server success
    output=$(ensure_openssh_server suse 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 1 when not installed on suse" 1 $result
    assertContains "Expecded ensure_openssh_server to suggest zypper install on failure" "$output" "sudo zypper install openssh-server"
}

test_ensure_openssh_server_installed_redhat() {
    mock_files=("/etc/ssh/sshd_config")         # /etc/ssh/sshd_config present
    mock_dirs=("/etc/ssh/sshd_config.d")        # /etc/ssh/sshd_config.d present
    mock_rpm_result=0                           # Simulate rpm -q openssh-server success
    output=$(ensure_openssh_server redhat 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 0 when installed on redhat" 0 $result
    assertEquals "Expecded ensure_openssh_server output to be empty on success" "" "$output"
}

test_ensure_openssh_server_not_installed_redhat() {
    mock_files=("/etc/ssh/sshd_config")         # /etc/ssh/sshd_config present
    mock_dirs=("/etc/ssh/sshd_config.d")        # /etc/ssh/sshd_config.d present
    mock_rpm_result=1                           # Simulate rpm -q openssh-server success
    output=$(ensure_openssh_server redhat 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 1 when not installed on redhat" 1 $result
    assertContains "Expecded ensure_openssh_server output to suggest dnf install failure" "$output" "sudo dnf install openssh-server"
}

test_ensure_openssh_server_installed_arch() {
    mock_files=("/etc/ssh/sshd_config")         # /etc/ssh/sshd_config present
    mock_dirs=("/etc/ssh/sshd_config.d")        # /etc/ssh/sshd_config.d present
    mock_pacman_result=0
    output=$(ensure_openssh_server arch 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 0 when installed on arch" 0 $result
    assertEquals "Expecded ensure_openssh_server output to be empty on success" "" "$output"
}

test_ensure_openssh_server_not_installed_arch() {
    mock_files=("/etc/ssh/sshd_config")         # /etc/ssh/sshd_config present
    mock_dirs=("/etc/ssh/sshd_config.d")        # /etc/ssh/sshd_config.d present
    mock_pacman_result=1
    output=$(ensure_openssh_server arch 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 1 when not installed on arch" 1 $result
    assertContains "Expecded ensure_openssh_server output to suggest dnf install failure" "$output" "sudo pacman -S openssh"
}

test_ensure_openssh_server_installed_debian() {
    mock_files=("/etc/ssh/sshd_config")         # /etc/ssh/sshd_config present
    mock_dirs=("/etc/ssh/sshd_config.d")        # /etc/ssh/sshd_config.d present
    mock_dpkg_result=0
    output=$(ensure_openssh_server debian 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 0 when installed on debian" 0 $result
    assertEquals "Expecded ensure_openssh_server output to be empty on success" "" "$output"
}

test_ensure_openssh_server_not_installed_debian() {
    mock_files=("/etc/ssh/sshd_config")         # /etc/ssh/sshd_config present
    mock_dirs=("/etc/ssh/sshd_config.d")        # /etc/ssh/sshd_config.d present
    mock_dpkg_result=1
    output=$(ensure_openssh_server debian 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 1 when not installed on debian" 1 $result
    assertContains "Expecded ensure_openssh_server output to suggest dnf install failure" "$output" "sudo apt install openssh-server"
}

test_ensure_openssh_server_installed_suse_configd_missing_config_d_exits() {
    mock_files=()                               # /etc/ssh/sshd_config not present
    mock_dirs=("/etc/ssh/sshd_config.d")        # /etc/ssh/sshd_config.d present
    mock_rpm_result=0                           # Simulate rpm -q openssh-server success
    output=$(ensure_openssh_server suse 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 0 when configd file is missing but config.d folder exists" 0 $result
    assertEquals "Expecded ensure_openssh_server output to be empty on success" "" "$output"
}

test_ensure_openssh_server_installed_suse_configd_exists_config_d_missing() {
    mock_files=("/etc/ssh/sshd_config")         # /etc/ssh/sshd_config present
    mock_dirs=()                                # /etc/ssh/sshd_config.d not present
    mock_rpm_result=0                           # Simulate rpm -q openssh-server success
    output=$(ensure_openssh_server suse 2>&1)
    result=$?

    assertEquals "Expected ensure_openssh_server to return 0 when configd is present but config.d folder exists" 0 $result
    assertEquals "Expecded ensure_openssh_server output to be empty on success" "" "$output"
}

test_ensure_openssh_server_installed_suse_config_missing() {
    mock_files=()          # /etc/ssh/sshd_config not present
    mock_dirs=()           # /etc/ssh/sshd_config.d not present
    mock_rpm_result=0      # Simulate rpm -q openssh-server success

    output=$(ensure_openssh_server suse 2>&1)
    result=$?

    assertEquals "Expected to fail if both ssh config and config.d are missing" 1 "$result"
    assertContains "Expected output missing config error" "$output" "Neither /etc/ssh/sshd_config nor /etc/ssh/sshd_config.d exists"
}

# shellcheck disable=SC1091
source shunit2
