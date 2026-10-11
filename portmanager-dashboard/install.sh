#!/usr/bin/env bash
# Primary Port Manager installer. Default: V2. Pass "v1" explicitly to install
# the original V1, unchanged. Do NOT use "sudo bash v1": bash treats it as a file.
set -Eeuo pipefail

REF="${PORTMANAGER_INSTALL_REF:-master}"
case "${1:-v2}" in
  v2|2|"") TARGET="portmanager-v2/install.sh" ;;
  v1|1) TARGET="portmanager-v1/install.sh" ;;
  *)
    printf '%s\n' 'Usage:'       '  curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash'       '  curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash -s -- v1' >&2
    exit 2
    ;;
esac
[[ "$(id -u)" -eq 0 ]] || { echo "Please run through sudo/root" >&2; exit 1; }
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo "Invalid source ref" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
tmp="$(mktemp)"
trap 'rm -f -- "$tmp"' EXIT
url="https://raw.githubusercontent.com/smorad3363/assistant-vps/$REF/$TARGET"
# Retry with a conservative TLS transport only after an SSL handshake failure.
# --tlsv1.2 alone sets the MINIMUM, not the maximum, TLS version.
download_https() {
  local url="$1" output="$2" status=0
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$url" -o "$output" || status=$?
  if ((status == 35)); then
    printf '%s\n' '[portmanager] TLS handshake failed; retrying with IPv4, HTTP/1.1 and TLS 1.2' >&2
    curl -4 --http1.1 --tlsv1.2 --tls-max 1.2 --proto '=https' -fsSL --retry 3 "$url" -o "$output"
  else
    return "$status"
  fi
}
if [[ "$TARGET" == "portmanager-v2/install.sh" ]]; then
  printf '[  0%%] Downloading installer\n'
fi
download_https "$url" "$tmp"
[[ -s "$tmp" ]] || { echo "Empty installer payload" >&2; exit 1; }
bash -n "$tmp"
if [[ "$TARGET" == "portmanager-v2/install.sh" ]]; then
  PORTMANAGER2_REF="${PORTMANAGER2_REF:-$REF}" bash "$tmp"
else
  PORTMANAGER_INSTALL_REF="$REF" bash "$tmp"
fi
