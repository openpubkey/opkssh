#!/bin/bash
export SHUNIT_RUNNIN=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

# Running tests

test_display_help_message() {
    output=$(display_help_message)
    expected_output=$(cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --no-home-policy         Disables configuration that allows opkssh see policy files in user's home directory
                           (/home/<username>/auth_id). Greatly simplifies install, try this if you are having install failures.
  --no-sshd-restart        Do not restart SSH after installation
  --overwrite-config       Overwrite the currently active sshd configuration for AuthorizedKeysCommand and AuthorizedKeysCommandUser
                           directives. This may be necessary if the script cannot create a configuration with higher priority in /etc/ssh/sshd_config.d/.
  --install-from=FILEPATH  Install using a local file
  --install-version=VER    Install a specific version from GitHub
  --help                   Display this help message
EOF
)
    assertEquals "Expected display_help_message to match expected output exactly" "$expected_output" "$output"
}

# shellcheck disable=SC1091
source shunit2
