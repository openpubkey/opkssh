#!/bin/bash

export SHUNIT_RUNNIN=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

export OS_TYPE="FOO"


setUp() {
    TEST_TEMP_DIR=$(mktemp -d /tmp/opkssh.XXXXXX)
    MOCK_LOG="$TEST_TEMP_DIR/mock.log"
    HOME_POLICY=true
    AUTH_CMD_USER="foo"
    AUTH_CMD_GROUP="bar"
    OS_TYPE=""

    parse_args_exit_code=0
    check_bash_version_exit_code=0
    running_as_root_exit_code=0
    determine_linux_type_exit_code=0
    check_cpu_architecture_exit_code=0
    ensure_command_wget_exit_code=0
    ensure_command_sudo_exit_code=0
    ensure_opkssh_user_and_group_exit_code=0
    ensure_openssh_server_exit_code=0
    install_opkssh_binary_exit_code=0
    configure_openssh_server_exit_code=0
    restart_openssh_server_exit_code=0
    export HOME_POLICY AUTH_CMD_USER AUTH_CMD_GROUP OS_TYPE
}

tearDown() {
    /usr/bin/rm -rf "$TEST_TEMP_DIR"
}

# Mock functions
parse_args() {
    echo "parse_args $*" >> "$MOCK_LOG"
    return "$parse_args_exit_code"
}

check_bash_version() {
    echo "check_bash_version $*" >> "$MOCK_LOG"
    return "$check_bash_version_exit_code"
}

running_as_root() {
    echo "running_as_root $*" >> "$MOCK_LOG"
    return "$running_as_root_exit_code"
}

determine_linux_type() {
    echo "determine_linux_type $*" >> "$MOCK_LOG"
    echo "FOO"
    return "$determine_linux_type_exit_code"
}

check_cpu_architecture() {
    echo "check_cpu_architecture $*" >> "$MOCK_LOG"
    echo "BAR"
    return "$check_cpu_architecture_exit_code"
}

ensure_command() {
    echo "ensure_command $*" >> "$MOCK_LOG"
    if [[ "$1" == "wget" ]]; then
        return "$ensure_command_wget_exit_code"
    elif [[ "$1" == "sudo" ]]; then
        return "$ensure_command_sudo_exit_code"
    else
        echo "!!!!!! THIS SHOULDN'T HAPPEN !!!!"
        exit 1
    fi
}

ensure_opkssh_user_and_group() {
    echo "ensure_opkssh_user_and_group $*" >> "$MOCK_LOG"
    return "$ensure_opkssh_user_and_group_exit_code"
}

ensure_openssh_server() {
    echo "ensure_openssh_server $*" >> "$MOCK_LOG"
    return "$ensure_openssh_server_exit_code"
}

install_opkssh_binary() {
    echo "install_opkssh_binary $*" >> "$MOCK_LOG"
    return "$install_opkssh_binary_exit_code"
}

check_selinux() {
    echo "check_selinux $*" >> "$MOCK_LOG"
}

configure_opkssh() {
    echo "configure_opkssh $*" >> "$MOCK_LOG"
}

configure_openssh_server() {
    echo "configure_openssh_server $*" >> "$MOCK_LOG"
    return "$configure_openssh_server_exit_code"
}

configure_sudo() {
    echo "configure_sudo $*" >> "$MOCK_LOG"
}

log_opkssh_installation() {
    echo "log_opkssh_installation $*" >> "$MOCK_LOG"
}

restart_openssh_server() {
    echo "restart_openssh_server $*" >> "$MOCK_LOG"
    return "$restart_openssh_server_exit_code"
}

# Tests

test_main_with_home_policy() {
    main AAA BBB
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 0 on success" 0 "$result"
    assertEquals "Expected parse_args to be called with correct parameters" "parse_args AAA BBB" "${mock_log[0]}"
    assertEquals "Expected check_bash_version to be called with correct parameters" "check_bash_version ${BASH_VERSINFO[*]}" "${mock_log[1]}"
    assertEquals "Expected running_as_root to be called with correct parameters" "running_as_root $EUID" "${mock_log[2]}"
    assertEquals "Expected determine_linux_type to be called with no parameters" "determine_linux_type " "${mock_log[3]}"
    assertEquals "Expected check_cpu_architecture to be called with no parameters" "check_cpu_architecture " "${mock_log[4]}"
    assertEquals "Expected ensure_command to be called with correct parameters" "ensure_command wget" "${mock_log[5]}"
    assertEquals "Expected ensure_command to be called with correct parameters" "ensure_command sudo" "${mock_log[6]}"
    assertEquals "Expected ensure_opkssh_user_and_group to be called with correct parameters" "ensure_opkssh_user_and_group foo bar" "${mock_log[7]}"
    assertEquals "Expected ensure_openssh_server to be called with correct parameters" "ensure_openssh_server FOO" "${mock_log[8]}"
    assertEquals "Expected install_opkssh_binary to be called with no parameters" "install_opkssh_binary " "${mock_log[9]}"
    assertEquals "Expected check_selinux to be called with no parameters" "check_selinux " "${mock_log[10]}"
    assertEquals "Expected configure_opkssh to be called with no parameters" "configure_opkssh " "${mock_log[11]}"
    assertEquals "Expected configure_openssh_server to be called with no parameters" "configure_openssh_server " "${mock_log[12]}"
    assertEquals "Expected restart_openssh_server to be called with no parameters" "restart_openssh_server " "${mock_log[13]}"
    assertEquals "Expected configure_sudo to be called with no parameters" "configure_sudo " "${mock_log[14]}"
    assertEquals "Expected log_opkssh_installation to be called with no parameters" "log_opkssh_installation " "${mock_log[15]}"
}

test_main_with_no_home_policy() {
    HOME_POLICY=false
    main AAA BBB
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 0 on success" 0 "$result"
    assertEquals "Expected parse_args to be called with correct parameters" "parse_args AAA BBB" "${mock_log[0]}"
    assertEquals "Expected check_bash_version to be called with correct parameters" "check_bash_version ${BASH_VERSINFO[*]}" "${mock_log[1]}"
    assertEquals "Expected running_as_root to be called with correct parameters" "running_as_root $EUID" "${mock_log[2]}"
    assertEquals "Expected determine_linux_type to be called with no parameters" "determine_linux_type " "${mock_log[3]}"
    assertEquals "Expected check_cpu_architecture to be called with no parameters" "check_cpu_architecture " "${mock_log[4]}"
    assertEquals "Expected ensure_command to be called with correct parameters" "ensure_command wget" "${mock_log[5]}"
    assertEquals "Expected ensure_opkssh_user_and_group to be called with correct parameters" "ensure_opkssh_user_and_group foo bar" "${mock_log[6]}"
    assertEquals "Expected ensure_openssh_server to be called with correct parameters" "ensure_openssh_server FOO" "${mock_log[7]}"
    assertEquals "Expected install_opkssh_binary to be called with no parameters" "install_opkssh_binary " "${mock_log[8]}"
    assertEquals "Expected check_selinux to be called with no parameters" "check_selinux " "${mock_log[9]}"
    assertEquals "Expected configure_opkssh to be called with no parameters" "configure_opkssh " "${mock_log[10]}"
    assertEquals "Expected configure_openssh_server to be called with no parameters" "configure_openssh_server " "${mock_log[11]}"
    assertEquals "Expected restart_openssh_server to be called with no parameters" "restart_openssh_server " "${mock_log[12]}"
    assertEquals "Expected log_opkssh_installation to be called with no parameters" "log_opkssh_installation " "${mock_log[13]}"
}


test_main_help_called() {
    parse_args_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 0 when help is called" 0 "$result"
    assertEquals "Expected that only parse_args function is called" 1 "${#mock_log[@]}"
}

test_main_check_bash_version_failes() {
    check_bash_version_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when fails" 1 "$result"
    assertEquals "Expected that only a few function are called" 2 "${#mock_log[@]}"
}

test_main_running_as_root_failes() {
    running_as_root_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when failes" 1 "$result"
    assertEquals "Expected that only a few function are called" 3 "${#mock_log[@]}"
}

test_main_determine_linux_type_failes() {
    determine_linux_type_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when failes" 1 "$result"
    assertEquals "Expected that only a few function are called" 4 "${#mock_log[@]}"
}

test_main_check_cpu_architecture_failes() {
    check_cpu_architecture_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when failes" 1 "$result"
    assertEquals "Expected that only a few function are called" 5 "${#mock_log[@]}"
}

test_main_ensure_command_wget_failes() {
    ensure_command_wget_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when failes" 1 "$result"
    assertEquals "Expected that only a few function are called" 6 "${#mock_log[@]}"
}

test_main_ensure_command_sudo_failes() {
    ensure_command_sudo_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when failes" 1 "$result"
    assertEquals "Expected that only a few function are called" 7 "${#mock_log[@]}"
}

test_main_ensure_opkssh_user_and_group_failes() {
    ensure_opkssh_user_and_group_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when failes" 1 "$result"
    assertEquals "Expected that only a few function are called" 8 "${#mock_log[@]}"
}

test_main_ensure_openssh_server_failes() {
    ensure_openssh_server_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when failes" 1 "$result"
    assertEquals "Expected that only a few function are called" 9 "${#mock_log[@]}"
}

test_main_install_opkssh_binary_failes() {
    install_opkssh_binary_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when failes" 1 "$result"
    assertEquals "Expected that only a few function are called" 10 "${#mock_log[@]}"
}


test_main_configure_openssh_server_failes() {
    configure_openssh_server_exit_code=1
    main
    result=$?

    readarray -t mock_log < "$MOCK_LOG"

    assertEquals "Expected result to return 1 when failes" 1 "$result"
    assertEquals "Expected that only a few function are called" 13 "${#mock_log[@]}"
}

# shellcheck disable=SC1091
source shunit2
