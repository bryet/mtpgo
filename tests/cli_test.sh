#!/bin/bash
# Offline entrypoint checks, using only a newly built binary and temporary files.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
GO=${GO:-go}
"$GO" build -trimpath -ldflags '-X mtproxy/version.Version=cli-regression' -o "$work/mtpgo" "$root/cmd/mtpgo"
secret=$("$work/mtpgo" -s)
[[ "$secret" =~ ^[0-9a-f]{32}$ ]]
"$work/mtpgo" -v | grep -q 'mtpgo version cli-regression'
"$work/mtpgo" -h >/dev/null 2>&1
# shellcheck source=mtproxy.sh
source "$root/mtproxy.sh"
cp "$root/config.example.ini" "$work/config.ini"
ini_set "$work/config.ini" SECRET "$secret"
"$work/mtpgo" -check -c "$work/config.ini"
[[ ! -f "$work/log_mtpgo" ]]
# Public example credentials must not be silently replaced or accepted.
ini_set "$work/config.ini" SECRET 00000000000000000000000000000000
if "$work/mtpgo" -check -c "$work/config.ini"; then exit 1; fi
printf '%s\n' 'CLI regression tests: PASS'
