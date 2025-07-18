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
  INSTALL_VERSION="latest"
  GITHUB_REPO="my-org/my-repo"
  HOME_POLICY=true

  result=$(get_te_download_path)
  expected="https://raw.githubusercontent.com/my-org/my-repo/v1.2.3/te_files/opkssh.te"

  assertEquals "$expected" "$result"
}

test_specific_version_equal_to_080() {
  INSTALL_VERSION="0.8.0"
  GITHUB_REPO="org/repo"
  HOME_POLICY=false

  result=$(get_te_download_path)
  expected="https://raw.githubusercontent.com/org/repo/main/te_files/opkssh-no-home.te"

  assertEquals "$expected" "$result"
}

test_get_te_download_path_specific_version_less_than_080() {
  INSTALL_VERSION="v0.6.0"
  GITHUB_REPO="org/repo"
  HOME_POLICY=true

  result=$(get_te_download_path)
  expected="https://raw.githubusercontent.com/org/repo/main/te_files/v0.7.0_opkssh.te"

  assertEquals "$expected" "$result"
}

test_get_te_download_path_specific_version_greater_than_080() {
  INSTALL_VERSION="1.0.0"
  GITHUB_REPO="org/repo"
  HOME_POLICY=false

  result=$(get_te_download_path)
  expected="https://raw.githubusercontent.com/org/repo/v1.0.0/te_files/opkssh-no-home.te"

  assertEquals "$expected" "$result"
}

# shellcheck disable=SC1091
source shunit2
