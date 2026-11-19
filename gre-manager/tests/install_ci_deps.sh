#!/usr/bin/env bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]]

install() {
  sudo apt-get "${apt_options[@]}" update -qq -o APT::Update::Error-Mode=any &&
    sudo apt-get "${apt_options[@]}" install -y -qq "$@"
}

apt_options=(-o Acquire::Retries=2 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15)
if install "$@"; then exit 0; fi

# The hosted mirror can time out. Use the signed Ubuntu archive over HTTPS on
# the disposable runner without changing the production installer.
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_CODENAME" =~ ^[a-z]+$ ]]
echo 'Retrying package installation using the signed Ubuntu HTTPS archive.'
fallback=$(mktemp)
trap 'rm -f -- "$fallback"' EXIT
cat >"$fallback" <<EOF
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu/ $VERSION_CODENAME main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu/ $VERSION_CODENAME-updates main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://security.ubuntu.com/ubuntu/ $VERSION_CODENAME-security main restricted universe multiverse
EOF
sudo install -m 0644 "$fallback" /etc/apt/gremgr-ci-sources.list
apt_options+=(-o Dir::Etc::sourcelist=/etc/apt/gremgr-ci-sources.list -o Dir::Etc::sourceparts=-)
install "$@"
