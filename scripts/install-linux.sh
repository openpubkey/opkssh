#!/usr/bin/env bash
# ==============================================================================
# Usage: install-linux.sh [OPTIONS]
#
# Options:
#   --no-home-policy
#       Disables configuration that allows opkssh to see policy files in user's
#       home directory (/home/<username>/auth_id). Greatly simplifies install.
#
#   --no-sshd-restart
#       Do not restart SSH after installation.
#
#   --overwrite-config
#       Overwrite the currently active sshd configuration for
#       AuthorizedKeysCommand and AuthorizedKeysCommandUser directives.
#
#   --install-from=FILEPATH
#       Install using a local file instead of downloading from GitHub.
#
#   --install-te-from=FILEPATH
#       Use local SELinux type enforcement file instead of downloading from GitHub
#
#   --install-version=VERSION
#       Install a specific version from GitHub instead of "latest".
#
#   --help
#       Display this help message.
# ==============================================================================
#

if [[ "$SHUNIT_RUNNING" != "1" ]]; then
    # Exit if any command fails, unless running tests
    set -e
fi

# Setting global variables

# OPKSSH_AUTH_CMD_USER
# Default: opksshuser
# Description: The system user responsible for executing the AuthorizedKeysCommand
AUTH_CMD_USER="${OPKSSH_INSTALL_AUTH_CMD_USER:-opksshuser}"

# OPKSSH_AUTH_CMD_GROUP
# Default: opksshuser
# Description: Group ownership for installed files and directories
AUTH_CMD_GROUP="${OPKSSH_INSTALL_AUTH_CMD_GROUP:-opksshuser}"

# OPKSSH_SUDOERS_PATH
# Default: /etc/sudoers.d/opkssh
# Description: Path to the sudoers file for opkssh
SUDOERS_PATH="${OPKSSH_INSTALL_SUDOERS_PATH:-/etc/sudoers.d/opkssh}"

# OPKSSH_HOME_POLICY
# Default: true
# Description: Whether to use the home directory policy feature
HOME_POLICY="${OPKSSH_INSTALL_HOME_POLICY:-true}"

# OPKSSH_RESTART_SSH
# Default: true
# Description: Whether to restart SSH after installation
RESTART_SSH="${OPKSSH_INSTALL_RESTART_SSH:-true}"

# OPKSSH_OVERWRITE_ACTIVE_CONFIG
# Default: false
# Description: Overwrite any existing active opkssh config
OVERWRITE_ACTIVE_CONFIG="${OPKSSH_INSTALL_OVERWRITE_ACTIVE_CONFIG:-false}"

# OPKSSH_LOCAL_INSTALL_FILE
# Default: (empty)
# Description: Path to local install file, used instead of downloading from GitHub
LOCAL_INSTALL_FILE="${OPKSSH_INSTALL_LOCAL_INSTALL_FILE:-}"

# OPKSSH_LOCAL_TE_FILE
# Default: (empty)
# Descriptiopn: path to local Type Enforcement file to install on SELinux enabled systems
LOCAL_TE_FILE="${OPKSSH_LOCAL_TE_FILE:-}"

# OPKSSH_INSTALL_VERSION
# Default: latest
# Description: Which version of opkssh to install from GitHub
INSTALL_VERSION="${OPKSSH_INSTALL_VERSION:-latest}"

# OPKSSH_INSTALL_DIR
# Default: /usr/local/bin
# Description: Where to install the opkssh binary
INSTALL_DIR="${OPKSSH_INSTALL_DIR:-/usr/local/bin}"

# OPKSSH_BINARY_NAME
# Default: opkssh
# Description: Name of the installed binary
BINARY_NAME="${OPKSSH_INSTALL_BINARY_NAME:-opkssh}"

# OPKSSH_GITHUB_REPO
# Default: openpubkey/opkssh
# Description: GitHub repository to download the opkssh binary from
GITHUB_REPO="${OPKSSH_INSTALL_GITHUB_REPO:-openpubkey/opkssh}"

# Global variables used by several functions
OS_TYPE=""
CPU_ARCH=""

# file_exists
# check is file exists, helpers that wrap real commands so it can be
# overridden in tests
#
# Arguments:
#   $1 - Path to file
#
# Returns:
#  0 if the file exists, otherwise
file_exists() { [[ -f "$1" ]]; }

# dir_exists
# check is directory exists, helpers that wrap real commands so it can be
# overridden in tests
#
# Arguments:
#   $1 - Path to directory
#
# Returns:
#  0 if the directory exists, otherwise
dir_exists() { [[ -d "$1" ]]; }

# check_bash_version
# Checks if a bash version is >= 3.2
#
# Arguments:
#   $1 - Major version
#   $2 - Minor version
#   $3 - Patch lever (optional, not used)
#   $4 - Build version (optional, not used)
#   $5 - Version string (optional, not used)
#   $6 - Vendor (optional, not used)
#   $7 - Operating system (optional, not used)
#
# Returns:
#   0 if version >= 3.2, 1 otherwise
#
# Example:
#   check_bash_version "${BASH_VERSINFO[@]}"
check_bash_version() {
    local major=$1
    local minor=$2

    if ((major > 3)); then
        echo "Bash version: $major.$minor"
        return 0
    elif ((major == 3 && minor >= 2)); then
        echo "Bash version: $major.$minor"
        return 0
    else
        echo "Error: Unsupported Bash version: $major.$minor" >&2
        return 1
    fi
}

# determine_linux_type
# Determine the linux type the script is executed in
#
# Outputs:
#   Writes the current Linux type detected
#
# Returns:
#   0 if successful, 1 if it's an unsupported OS
determine_linux_type() {
    local os_type
    if file_exists "/etc/redhat-release" ; then
        os_type="redhat"
    elif file_exists "/etc/debian_version" ; then
        os_type="debian"
    elif file_exists "/etc/arch-release"; then
        os_type="arch"
    elif file_exists "/etc/os-release" && \
        grep -q '^ID_LIKE=.*suse' /etc/os-release; then
        os_type="suse"
    else
        echo "Unsupported OS type."
        return 1
    fi
    echo "$os_type"
}

# check_cpu_architecture
# Checks the CPU architecture the script is running on
#
# Outputs:
#   Writes the CPU architechture the script is runnin on
#
# Returns:
#   0 if running on supported architectur, 1 otherwise
check_cpu_architecture() {
    local cpu_arch
    cpu_arch="$(uname -m)"
    case "$cpu_arch" in
        x86_64)
            cpu_arch="amd64"
            ;;
        aarch64)
            cpu_arch="arm64"
            ;;
        amd64 | arm64)
            # Supported architectures, no changes needed
            ;;
        *)
            echo "Error: Unsupported CPU architecture: $cpu_arch." >&2
            return 1
            ;;
    esac
    echo "$cpu_arch"
}

# running_as_root
# Checks if the script executes as root
#
# Arguments:
#   $1 - UID of user to check
#
# Returns:
#   0 if running as root, 1 otherwise
running_as_root() {
    userid="$1"
    if [[ "$userid" -ne 0 ]]; then
        echo "Error: This script must be run as root." >&2
        echo "sudo $0" >&2
        return 1
    fi
}

# display_help_message
# Prints script help message to stdout
#
# Returns:
#   0 on success
display_help_message() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-home-policy            Disables configuration that allows opkssh see policy files in user's home directory"
    echo "                              (/home/<username>/auth_id). Greatly simplifies install, try this if you are having install failures."
    echo "  --no-sshd-restart           Do not restart SSH after installation"
    echo "  --overwrite-config          Overwrite the currently active sshd configuration for AuthorizedKeysCommand and AuthorizedKeysCommandUser"
    echo "                              directives. This may be necessary if the script cannot create a configuration with higher priority in /etc/ssh/sshd_config.d/."
    echo "  --install-from=FILEPATH     Install using a local file"
    echo "  --install-te-from=FILEPATH  Install SELinux Type Enforcement using a local file"
    echo "  --install-version=VER       Install a specific version from GitHub"
    echo "  --help                      Display this help message"
}

# ensure_command
# Checks whether a given command is available on the system.
#
# Arguments:
#   $1 - Name of the command to check (e.g. "curl", "git", "netstat").
#   $2 - Name of the package the command is delivered in (e.g. "curl", "git", "net-tools-deprecated" (optional, defauls to $1)
#   $3 - OS Type the script is running on, output from function determine_linux_type (optional, default so OS_TYPE)
#
# Outputs:
#   Writes an error message to stderr if the command is missing and how to install the command on supported OS types.
#
# Returns:
#   0 if the command is found, 1 otherwise.
#
# Example:
#   ensure_command "wget" || exit 1
#   ensure_command "netstat" "net-tools-deprecated" || exit
ensure_command() {
    local cmd="$1"
    local package="${2:-$cmd}"
    local os_type="${3:-$OS_TYPE}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: $cmd is not installed. Please install it first." >&2
        if [[ "$os_type" == "debian" ]]; then
            echo "sudo apt install $package" >&2
        elif [[ "$os_type" == "redhat" ]]; then
            # dnf might not be available on older versions
            if command -v dnf >/dev/null 2>&1; then
                echo "sudo dnf install $package" >&2
            else
                echo "sudo yum install $package" >&2
            fi
        elif [[ "$os_type" == "arch" ]]; then
            echo "sudo pacman -S $package" >&2
        elif [[ "$os_type" == "suse" ]]; then
            echo "sudo zypper install $package" >&2
        else
            echo "Unsupported OS type." >&2
        fi
        return 1
    fi
}

# ensure_openssh_server
# Ensures that openSSH-Server is installed and configuration targets exists
#
# Arguments:
#   $1 - OS Type the script is running on, output from function determine_linux_type
#
# Outputs:
#   Writes error if openSSH isn't installed with package manager
#   Writes error if it could verify target configuration files for opkssh
#
# Returns:
#   0 if openSSH is installed with package manager and configuration files exists, 1 otherwise.
ensure_openssh_server() {
    local os_type="$1"
    case "$os_type" in
        redhat)
            if ! rpm -q openssh-server &>/dev/null; then
                echo "OpenSSH server is NOT installed." >&2
                echo "To install it, run: sudo dnf install openssh-server" >&2
                return 1
            fi
            ;;
        debian)
            if ! dpkg -l | grep -q '^ii.*openssh-server'; then
                echo "OpenSSH server is NOT installed." >&2
                echo "To install it, run: sudo apt install openssh-server" >&2
                return 1
            fi
            ;;
        arch)
            if ! pacman -Q openssh &>/dev/null; then
                echo "OpenSSH server is NOT installed." >&2
                echo "To install it, run: sudo pacman -S openssh" >&2
                return 1
            fi
            ;;
        suse)
            if ! rpm -q openssh-server &>/dev/null; then
                echo "OpenSSH server is NOT installed." >&2
                echo "To install it, run: sudo zypper install openssh-server" >&2
                return 1
            fi
            ;;
    esac
    # Ensure OpenSSH server configuration targets exists
    if ! file_exists /etc/ssh/sshd_config && ! dir_exists /etc/ssh/sshd_config.d; then
        echo "Neither /etc/ssh/sshd_config nor /etc/ssh/sshd_config.d exists." >&2
        return 1
    fi
}

# ensure_opkssh_user_and_group
# Checks if the group and user used bu AuthorizedKeysCommand exists if not creates it
#
# Arguments:
#   $1 - AuthorizedKeysCommand User
#   $2 - AuthorizedKeysCommand Group
#
# Outputs:
#   Writes to stdout if group created and if user is created
#
# Returns:
#   0 on success
ensure_opkssh_user_and_group() {
    local auth_cmd_user="$1"
    local auth_cmd_group="$2"
    # Checks if the group used by the AuthorizedKeysCommand exists if not creates it
    if ! getent group "$auth_cmd_group" >/dev/null; then
        groupadd --system "$auth_cmd_group"
        echo "Created group: $auth_cmd_group"
    fi
    # If the AuthorizedKeysCommand user does not exist, create it and add it to the group
    if ! getent passwd "$auth_cmd_user" >/dev/null; then
        useradd -r -M -s /sbin/nologin -g "$auth_cmd_group" "$auth_cmd_user"
        echo "Created user: $auth_cmd_user with group: $auth_cmd_group"
    else
        # If the AuthorizedKeysCommand user exist, ensure it is added to the group
        usermod -aG "$auth_cmd_group" "$auth_cmd_user"
        echo "Added $auth_cmd_user to group: $auth_cmd_group"
    fi
}

# get_te_download_path
# Checks the INSTALL_VERSION to determin where to download the TE file to download
#
# Outputs:
#   The URL to download the TE file to use
get_te_download_path() {
    local te_url version
    if [[ "$INSTALL_VERSION" == "latest" ]]; then
        version=$(wget --server-response --max-redirect=0 -O /dev/null "https://github.com/${GITHUB_REPO}/releases/latest" 2>&1 | sed -n -E 's/^  Location: .*\/tag\/(v[0-9.]+).*/\1/p')
    else
        version="$INSTALL_VERSION"
    fi
    te_url="https://raw.githubusercontent.com/${GITHUB_REPO}/refs/tags/${version}/te-files/opkssh"

    if [[ "$HOME_POLICY" == true ]]; then
        te_url="${te_url}.te"
    else
        te_url="${te_url}-no-home.te"
    fi

    echo "$te_url"
}

# check_opkssh_version
# Checks if an earlier version that is not supported by this script is beeing installed
# If so, exit with error code and installation instructions
#
# Outputs:
#   Nothing is version is supported else outputs install instructions to stderr
#
# Returns:
#  0 on success
#  1 if INSTALL_VERSION isn't supported
check_opkssh_version() {
    local min_version="v0.9.0"

    [[ "$INSTALL_VERSION" == "latest" ]] && return 0

    if [[ ! "$(printf '%s\n' "$min_version" "$INSTALL_VERSION" | sed 's/^v//' | sort -V | head -n1)" = "${min_version#v}" ]]; then
        echo "Installing opkssh $INSTALL_VERSION with this script isn't supported" >&2
        echo "Use the following command to install $INSTALL_VERSION:" >&2
        echo "wget -qO- https://raw.githubusercontent.com/$GITHUB_REPO/refs/tags/$INSTALL_VERSION/scripts/install-linux.sh | sudo bash -s -- --install-version=$INSTALL_VERSION" >&2
        return 1
    fi
}

# parse_args
# Parses CLI arguments and sets configuration flags.
#
# Arguments:
#   $@ - Command-line arguments
#
# Outputs:
#   Sets global variables: HOME_POLICY, RESTART_SSH, OVERWRITE_ACTIVE_CONFIG,LOCAL_INSTALL_FILE, INSTALL_VERSION.
#
# Returns:
#   0 on success, 1 if help is in arguments
parse_args() {
    for arg in "$@"; do
        if [[ "$arg" == "--no-home-policy" ]]; then
            HOME_POLICY=false
        elif [[ "$arg" == "--help" ]]; then
            display_help_message
            return 1
        elif [[ "$arg" == "--no-sshd-restart" ]]; then
            RESTART_SSH=false
        elif [[ "$arg" == "--overwrite-config" ]]; then
            OVERWRITE_ACTIVE_CONFIG=true
        elif [[ "$arg" == --install-from=* ]]; then
            LOCAL_INSTALL_FILE="${arg#*=}"
        elif [[ "$arg" == --install-te-from=* ]]; then
            LOCAL_TE_FILE="${arg#*=}"
        elif [[ "$arg" == --install-version=* ]]; then
            INSTALL_VERSION="${arg#*=}"
        fi
    done
}

# install_opkssh_binary
# Installs opkssh binary either from local file or downloads from repository
#
# Outputs:
#   Writes to stdout if installing from local file or repository or the URL from wher it's downloaded
#   Writes to stderr if install path doesn't exist
#
# Returns:
#   0 if installation is succeeded, 1 otherwise
install_opkssh_binary() {
    # Check if we should install from a local file
    if [[ -n "$LOCAL_INSTALL_FILE" ]]; then
        echo "LOCAL_INSTALL_FILE is set, installing from local file: $LOCAL_INSTALL_FILE"
        BINARY_PATH=$LOCAL_INSTALL_FILE
        if [[ ! -f "$BINARY_PATH" ]]; then
            echo "Error: Specified binary path does not exist." >&2
            return 1
        fi
        echo "Using binary from specified path: $BINARY_PATH"
    else
        if [[ "$INSTALL_VERSION" == "latest" ]]; then
            BINARY_URL="https://github.com/$GITHUB_REPO/releases/latest/download/opkssh-linux-$CPU_ARCH"
        else
            BINARY_URL="https://github.com/$GITHUB_REPO/releases/download/$INSTALL_VERSION/opkssh-linux-$CPU_ARCH"
        fi

        # Download the binary
        echo "Downloading version $INSTALL_VERSION of $BINARY_NAME from $BINARY_URL..."
        wget -q --show-progress -O "$BINARY_NAME" "$BINARY_URL"

        BINARY_PATH="$BINARY_NAME"
    fi

    # Move to installation directory
    mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"

    # Make the binary executable, correct permissions/ownership
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    chown root:"${AUTH_CMD_GROUP}" "$INSTALL_DIR/$BINARY_NAME"
    chmod 755 "$INSTALL_DIR/$BINARY_NAME"

    if command -v "$INSTALL_DIR"/"$BINARY_NAME" &>/dev/null; then
        echo "Installed $BINARY_NAME to $INSTALL_DIR/$BINARY_NAME"
    else
        echo "Installation failed." >&2
        return 1
    fi
}

# check_selinux
#   Checks if SELinux is enabled and if so, ensures the context is set correctly
#
# Outputs:
#   Progress of SELinux context installation/configuration or message that SELinux is disabled
#
# Returns:
#   0 if SELinux is disabled or if context is correctly
check_selinux() {
    local te_tmp mod_tmp pp_tmp
    if command -v getenforce >/dev/null 2>&1; then
        if [[ "$(getenforce)" != "Disabled" ]]; then
            echo "SELinux detected. Configuring SELinux for opkssh"
            echo "  Restoring context for $INSTALL_DIR/$BINARY_NAME..."
            restorecon "$INSTALL_DIR/$BINARY_NAME"

            if [[ "$HOME_POLICY" == true ]]; then
                echo "  Using SELinux module that permits home policy"
                # Create temporary files for the compiled module and package
                te_tmp="/tmp/opkssh.te"
                mod_tmp="/tmp/opkssh.mod" # SELinux requires that modules have the same file name as the module name
                pp_tmp="/tmp/opkssh.pp"
            else
                echo "  Using SELinux module does not permits home policy (--no-home-policy option supplied)"
                # Redefine the tmp file names since SELinux modules must have the same name as the file
                te_tmp="/tmp/opkssh-no-home.te"
                mod_tmp="/tmp/opkssh-no-home.mod" # SELinux requires that modules have the same file name as the module name
                pp_tmp="/tmp/opkssh-no-home.pp"
            fi

            if [[ -n "$LOCAL_TE_FILE" ]]; then
                echo "  Using local TE-file"
                cp "$LOCAL_TE_FILE" "$te_tmp"
            else
                echo "  Downloading TE-file"
                wget -q -O "$te_tmp" "$(get_te_download_path)"
            fi

            echo "  Compiling SELinux module..."
            checkmodule -M -m -o "$mod_tmp" "$te_tmp"

            echo "  Packaging module..."
            semodule_package -o "$pp_tmp" -m "$mod_tmp"

            echo "  Installing module..."
            semodule -i "$pp_tmp"

            rm -f "$te_tmp" "$mod_tmp" "$pp_tmp"
            echo "SELinux module installed successfully!"
        fi
    else
        echo "SELinux is disabled"
    fi
}

# configure_opkssh
# Creates/checks the opskssh configuration
#
# Arguments:
#   $1 - Path to etc directory (Optional, default /etc)
#
# Outputs:
#   Writes to stdout the configration progress
#
# Returns:
#   0
# shellcheck disable=SC2120
configure_opkssh() {
    local etc_path="${1:-/etc}"
    # Define the default OpenID Providers
    local provider_google="https://accounts.google.com 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com 24h"
    local provider_microsoft="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h"
    local provider_gitlab="https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h"
    local provider_hello="https://issuer.hello.coop app_xejobTKEsDNSRd5vofKB2iay_2rN 24h"

    echo "Configuring opkssh:"

    if [[ ! -e "$etc_path/opk" ]]; then
        mkdir -p "$etc_path/opk"
        chown root:"${AUTH_CMD_GROUP}" "$etc_path/opk"
        chmod 750 "$etc_path/opk"
    fi

    if [[ ! -e "$etc_path/opk/policy.d" ]]; then
        mkdir -p "$etc_path/opk/policy.d"
        chown root:"${AUTH_CMD_GROUP}" "$etc_path/opk/policy.d"
        chmod 750 "$etc_path/opk/policy.d"
    fi

    if [[ ! -e "$etc_path/opk/auth_id" ]]; then
        touch "$etc_path/opk/auth_id"
        chown root:"${AUTH_CMD_GROUP}" "$etc_path/opk/auth_id"
        chmod 640 "$etc_path/opk/auth_id"
    fi

    if [[ ! -e "$etc_path/opk/config.yml" ]]; then
        touch "$etc_path/opk/config.yml"
        chown root:"${AUTH_CMD_GROUP}" "$etc_path/opk/config.yml"
        chmod 640 "$etc_path/opk/config.yml"
    fi

    if [[ ! -e "$etc_path/opk/providers" ]]; then
        touch "$etc_path/opk/providers"
        chown root:"${AUTH_CMD_GROUP}" "$etc_path/opk/providers"
        chmod 640 "$etc_path/opk/providers"
    fi

    if [[ -s "$etc_path/opk/providers" ]]; then
        echo "  The providers policy file (/etc/opk/providers) is not empty. Keeping existing values"
    else
        {
            echo "$provider_google"
            echo "$provider_microsoft"
            echo "$provider_gitlab"
            echo "$provider_hello"
        } >> "$etc_path/opk/providers"
    fi
}

# configure_openssh_server
# Configure openSSH-server to use opkssh using AuthorizedKeysCommand
#
# Arguments:
#   $1 - Path to ssh root configuration directory (Optional, default /etc/ssh)
#
# Output:
#   Writes to stdout the progress of configuration
#
# Returns:
#   0 if succeeded, otherwise 1
# shellcheck disable=SC2120
configure_openssh_server() {
    local ssh_root="${1:-/etc/ssh}"
    local sshd_config="$ssh_root/sshd_config"
    local sshd_config_d="$ssh_root/sshd_config.d"
    local auth_key_cmd="AuthorizedKeysCommand ${INSTALL_DIR}/${BINARY_NAME} verify %u %k %t"
    local auth_key_user="AuthorizedKeysCommandUser ${AUTH_CMD_USER}"
    local opk_config_suffix="opk-ssh.conf"
    local new_prefix=""
    local active_config=""

    if [[ ! -f "$sshd_config" ]] || \
        (grep -Fxq 'Include /etc/ssh/sshd_config.d/*.conf' "$sshd_config" &&
            { ! grep -Eq '^AuthorizedKeysCommand|^AuthorizedKeysCommandUser' "$sshd_config" ||
                ! grep -Eq '^AuthorizedKeysCommand|^AuthorizedKeysCommandUser' "$sshd_config_d"/*.conf 2>/dev/null; }); then
        # Configuration should be put in /etc/ssh/sshd_config.d director
        # Find active configuration file with the directives we're interested in (sorted numerically)
        active_config=$(find "$sshd_config_d"/*.conf -exec grep -l '^AuthorizedKeysCommand\|^AuthorizedKeysCommandUser' {} \; 2>/dev/null | sort -V | head -n 1)

        if [[ "$active_config" == *"$opk_config_suffix" ]] || [[ "$OVERWRITE_ACTIVE_CONFIG" == true ]]; then
            # Overwrite the configuration, either from a previous run of this script or because user request it for the currently active config
            sed -i '/^AuthorizedKeysCommand /s/^/#/' "$active_config"
            sed -i '/^AuthorizedKeysCommandUser /s/^/#/' "$active_config"
            echo "$auth_key_cmd" >> "$active_config"
            echo "$auth_key_user" >> "$active_config"
        elif [[ "$(basename "$active_config")" =~ ^0+[^0-9]+ ]]; then
            # The active config starts with all zeros and is therefore the one with the
            # highest priority. We cannot add a new file with even higher priority.
            echo "  Cannot create configuration with higher priority. Remove $active_config or rerun the script with the --overwrite-config flag to overwrite"
            return 1
        else
            if [[ -z "$active_config" ]]; then
                # No active configuration found, let's set a default prefix
                new_prefix=60
            else
                # Create a new config file with higher priority
                prefix=$(basename "$active_config" | grep -o '^[0-9]*')
                new_prefix=$((prefix - 1))
            fi
            new_config="${sshd_config_d}/${new_prefix}-$opk_config_suffix"
            echo "$auth_key_cmd" > "$new_config"
            echo "$auth_key_user" >> "$new_config"
        fi
    else
        # The directives in 'sshd_config' are active
        sed -i '/^AuthorizedKeysCommand /s/^/#/' "$sshd_config"
        sed -i '/^AuthorizedKeysCommandUser /s/^/#/' "$sshd_config"
        echo "$auth_key_cmd" >> "$sshd_config"
        echo "$auth_key_user" >> "$sshd_config"
    fi
}

# restart_openssh_server
# Checks if RESTART_SSH is true and restarts the openSSH server daemon if that is the case
#
# Outputs:
#   Writes to stdout the status if the daemon is restarted
#   Writes to stdout is set to false and skipping daemon restart
#
# Returns:
#   0 if successful, 1 if it's an unsupported OS_TYPE
restart_openssh_server() {
    if [[ "$RESTART_SSH" == true ]]; then
        if [[ "$OS_TYPE" == "debian" ]]; then
            systemctl restart ssh
        elif [[ "$OS_TYPE" == "redhat" ]] || [[ "$OS_TYPE" == "arch" ]] || [[ "$OS_TYPE" == "suse" ]]; then
            systemctl restart sshd
        else
            echo "  Unsupported OS type."
            return 1
        fi
    else
        echo "  RESTART_SSH is not true, skipping SSH restart."
    fi
}

# configure_sudo
# Configures sudo for opkssh if HOME_POLICY is set to true
#
# Outputs:
#   Writes to stdout the progress of sudo configuration if HOME_POLICY=true
#   Writes to stdout that sudo is not configured if HOME_POLICY=false
#
# Returns:
#   0
configure_sudo() {
    if [[ "$HOME_POLICY" == true ]]; then
        if [[ ! -f "$SUDOERS_PATH" ]]; then
            echo "  Creating sudoers file at $SUDOERS_PATH..."
            touch "$SUDOERS_PATH"
            chmod 440 "$SUDOERS_PATH"
        fi
        SUDOERS_RULE_READ_HOME="$AUTH_CMD_USER ALL=(ALL) NOPASSWD: ${INSTALL_DIR}/${BINARY_NAME} readhome *"
        if ! grep -qxF "$SUDOERS_RULE_READ_HOME" "$SUDOERS_PATH"; then
            echo "  Adding sudoers rule for $AUTH_CMD_USER..."
            echo "# This allows opkssh to call opkssh readhome <username> to read the user's policy file in /home/<username>/auth_id" >> "$SUDOERS_PATH"
            echo "$SUDOERS_RULE_READ_HOME" >> "$SUDOERS_PATH"
        fi
    else
        echo "  Skipping sudoers configuration as it is only needed for home policy (HOME_POLICY is set to false)"
    fi
}



# log_opkssh_installation
# Log the installation details to /var/log/opkssh.log to help with debugging
#
# Arguments:
#   $1 - Path to opkssh log file (Optional, default /var/log/opkssh.log)
#
# Output:
#   Writes to stdout that installation is successful
#   Writes installation debug information to /var/log/opkssh.log
#
# Returns:
#   0
# shellcheck disable=SC2120
log_opkssh_installation() {
    local log_file="${1:-/var/log/opkssh.log}"
    touch "$log_file"
    chown root:"${AUTH_CMD_GROUP}" "$log_file"
    chmod 660 "$log_file"

    VERSION_INSTALLED=$("$INSTALL_DIR"/"$BINARY_NAME" --version)
    INSTALLED_ON=$(date)
    # Log the installation details to /var/log/opkssh.log to help with debugging
    echo "Successfully installed opkssh (INSTALLED_ON: $INSTALLED_ON, VERSION_INSTALLED: $VERSION_INSTALLED, INSTALL_VERSION: $INSTALL_VERSION, LOCAL_INSTALL_FILE: $LOCAL_INSTALL_FILE, HOME_POLICY: $HOME_POLICY, RESTART_SSH: $RESTART_SSH)" >> "$log_file"

    echo "Installation successful! Run '$BINARY_NAME' to use it."
}

# main
# Running main function only if executed, not sourced
#
# Arguments:
#   "$@"
#
# Returns:
#   0 if opkssh installs successfully, 1 if installation failed
main() {
    parse_args "$@" || return 0
    check_bash_version "${BASH_VERSINFO[@]}" || return 1
    check_opkssh_version || return 1
    running_as_root "$EUID" || return 1
    OS_TYPE=$(determine_linux_type) || return 1
    CPU_ARCH=$(check_cpu_architecture) || return 1
    ensure_command "wget" || return 1
    if [[ "$HOME_POLICY" == true ]]; then
        ensure_command "sudo" || return 1
    fi
    ensure_opkssh_user_and_group "$AUTH_CMD_USER" "$AUTH_CMD_GROUP" || return 1
    ensure_openssh_server "$OS_TYPE" || return 1
    install_opkssh_binary || return 1
    check_selinux
    configure_opkssh
    configure_openssh_server || return 1
    restart_openssh_server || return 1
    if [[ "$HOME_POLICY" == true ]]; then
        configure_sudo
    fi
    log_opkssh_installation
}

# Don't run main during testing (SH unit tests source this script)
if [[ -z "$SHUNIT_RUNNING" ]]; then
    main "$@"
    exit $?
fi
