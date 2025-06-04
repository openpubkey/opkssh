#!/bin/bash
export SHUNIT_RUNNIN=1

echo "Running tests: ${0##*/}"

# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

#
# Override functions for mocking
#
file_exists() {
    [[ " ${mock_files[*]} " == *" $1 "* ]]
}

# Mock uname -m
uname() {
    if [[ "$1" == "-m" ]]; then
        echo "$mock_uname_arch"
        return 0
    fi
    /usr/bin/uname "$@"
}

# Mock grep -q '^ID_LIKE=.*suse'
grep() {
    if [[ "$1" == "-q" && "$2" == "^ID_LIKE=.*suse" ]]; then
        if [[ "$mock_grep_suse" -eq 0 ]]; then
            return 0
        else
            return 1
        fi
    fi
    /usr/bin/grep "$@"
}

# Mock command -v
command() {
    if [[ "$1" == "-v" && "$2" == "$mock_command_name" ]]; then
        if [[ "$mock_command_exists" == "true" ]]; then
            echo "/usr/bin/$2"
            return 0
        else
          return 1
        fi
    fi
    builtin command "$@"  # fall back to real command
}


# Running tests

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
    mock_grep_suse=0
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return success (0) for /etc/os-release and greping 'ID_LIKE=suse'" 0 $result
    assertEquals "Expected the output to equal 'suse' for /etc/os-release" "suse" "$output"
}

test_determine_linux_type_os_release_non_suse() {
    mock_files=("/etc/os-release")
    mock_grep_suse="1"
    output=$(determine_linux_type "")
    result=$?
    assertEquals "Expected determine_linux_type to return failure (1) for /etc/os-release and greping 'ID_LIKE=ubuntu'" 1 $result
    assertEquals "Expected the output to equal 'Unsupported OS type.' for /etc/os-release greping 'ID_LIKE=ubuntu" "Unsupported OS type." "$output"
}

test_determine_linux_type_unsupported_os() {
    mock_files=()
    mock_grep_suse="0"
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

test_display_help_message() {
    output=$(display_help_message)
    expected_output=$(cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --no-home-policy         Disables configuration that allows opkssh see policy files in user's home directory (/home/<username>/auth_id). Greatly simplifies install, try this if you are having install failures.
  --no-sshd-restart        Do not restart SSH after installation
  --overwrite-config       Overwrite the currently active sshd configuration for AuthorizedKeysCommand and AuthorizedKeysCommandUser directives. This may be necessary if the script cannot create a configuration with higher priority in /etc/ssh/sshd_config.d/.
  --install-from=FILEPATH  Install using a local file
  --install-version=VER    Install a specific version from GitHub
  --help                   Display this help message
EOF
)
    assertEquals "Expected display_help_message to match expected output exactly" "$expected_output" "$output"
}

test_ensure_command_exists() {
    mock_command_name="curl"
    mock_command_exists=true
    output=$(ensure_command "curl" "curl" "debian" 2>&1)
    result=$?

    assertEquals "Expected ensure_command_exists to return 0 when command exists" 0 $result
    assertEquals "Expected ensure_command_exists to not output anything when command exists" "" "$output"
}


test_ensure_command_missing_using_variables() {
    mock_command_name="foobar"
    mock_command_exists=false
    # shellcheck disable=2034  # used in ensure_command
    OS_TYPE=suse 
    output=$(ensure_command "foobar" 2>&1)
    result=$?

    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to prompt to install on suse" "$output" "sudo zypper install foobar"
}

test_ensure_command_missing_debian() {
    mock_command_name="curl"
    mock_command_exists=false
    output=$(ensure_command "curl" "curl" "debian" 2>&1)
    result=$?

    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to prompt to install on debian" "$output" "sudo apt install curl"
}

test_ensure_command_missing_redhat_with_dnf() {
    mock_command_name="curl"
    mock_command_exists=false

    # Also mock dnf existence
    # shellcheck disable=2317
    command() {
        if [[ "$1" == "-v" && "$2" == "dnf" ]]; then
            return 0  # dnf exists
        fi
        if [[ "$1" == "-v" && "$2" == "$mock_command_name" ]]; then
            return 1  # command is missing
        fi
        builtin command "$@"
    }

    output=$(ensure_command "curl" "curl" "redhat" 2>&1)
    result=$?

    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to suggest dnf for redhat if available" "$output" "sudo dnf install curl"
}


test_ensure_command_missing_redhat_without_dnf() {
    mock_command_name="curl"
    mock_command_exists=false
    # Also mock dnf existence
    # shellcheck disable=2317
    command() {
        if [[ "$1" == "-v" && "$2" == "dnf" ]]; then
            return 1  # dnf is missing
        fi
        if [[ "$1" == "-v" && "$2" == "$mock_command_name" ]]; then
            return 1  # command is missing
        fi
        builtin command "$@"
    }

    output=$(ensure_command "curl" "curl" "redhat" 2>&1)
    result=$?

    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to suggest dnf for redhat if available" "$output" "sudo yum install curl"
}

test_ensure_command_missing_arch() {
    mock_command_name="curl"
    mock_command_exists=false
    output=$(ensure_command "curl" "curl" "arch" 2>&1)
    result=$?

    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to suggest pacman for arch" "$output" "sudo pacman -S curl"
}

test_ensure_command_missing_suse() {
    mock_command_name="curl"
    mock_command_exists=false
    output=$(ensure_command "curl" "curl" "suse" 2>&1)
    result=$?

    assertEquals "Expected ensure_command_exists to return 1 when command is missing" 1 $result
    assertContains "Expected ensure_command_exists to suggest zypper for suse" "$output" "sudo zypper install curl"
}

test_ensure_command_unsupported_os() {
    mock_command_name="curl"
    mock_command_exists=true
    output=$(ensure_command "curl" "curl" "foobar" 2>&1)
    result=$?

    assertEquals "Expected ensure_command_exists to return 1 when it is an Unsupported OS" 1 $result
    assertContains "Expected ensure_command_exists to warn about unsupported OS" "$output" "Unsupported OS type."
}

# shellcheck disable=SC1091
source shunit2
