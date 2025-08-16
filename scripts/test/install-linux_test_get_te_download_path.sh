#!/bin/bash
export SHUNIT_RUNNING=1


# Source install-linux.sh
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/../install-linux.sh"

# Override wget for testing "latest"
wget() {
    echo "  Location: https://github.com/${GITHUB_REPO}/releases/tag/v1.2.3"
}

test_get_te_download_path_latest_version_with_home_policy_true() {
    export INSTALL_VERSION="latest"
    export GITHUB_REPO="my-org/my-repo"
    export HOME_POLICY=true

    result=$(get_te_download_path)
    expected="https://raw.githubusercontent.com/my-org/my-repo/v1.2.3/te_files/opkssh.te"

    assertEquals "$expected" "$result"
}

test_specific_version_no_home() {
    export INSTALL_VERSION="v1.0.0"
    export GITHUB_REPO="org/repo"
    export HOME_POLICY=false

    result=$(get_te_download_path)
    expected="https://raw.githubusercontent.com/org/repo/v1.0.0/te_files/opkssh-no-home.te"

    assertEquals "$expected" "$result"
}

# shellcheck disable=SC1091
source shunit2
