#!/bin/bash
# All service/network/account operations are stubbed; files stay in a temp tree.
# Stubs intentionally replace sourced functions in successive test phases.
# shellcheck disable=SC2317,SC2218
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=mtproxy.sh
source "$root/mtproxy.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export TMPDIR="$work"
# Production ignores TMPDIR for release staging and always uses private /tmp.
stage=$(new_staging_dir)
[[ "$stage" == /tmp/mtpgo.* && "$stage" != "$work/"* ]]
[[ $(stat -c %a "$stage") == 700 ]]
[[ -z "$(ls -A "$stage")" ]]
rmdir "$stage"

assert_equal() { [[ "$1" == "$2" ]] || { printf 'expected %q, got %q\n' "$2" "$1" >&2; exit 1; }; }

printf 'SECRET = old\nPORT=12345\n' > "$work/edit.ini"
ini_set "$work/edit.ini" SECRET new
assert_equal "$(ini_get "$work/edit.ini" SECRET)" new
assert_equal "$(ini_get "$work/edit.ini" PORT)" 12345
ini_set "$work/edit.ini" MASK false
assert_equal "$(ini_get "$work/edit.ini" MASK)" false

# Build a fixture archive, then serve it through a curl stub without network.
mkdir "$work/fixture"
printf binary > "$work/fixture/mtpgo"
printf config > "$work/fixture/config.ini"
printf service > "$work/fixture/mtpgo.service"
printf openrc > "$work/fixture/mtpgo_openrc"
archive=mtpgo-linux-arm64.tar.gz
arch=arm64
tar -czf "$work/$archive" -C "$work/fixture" mtpgo config.ini mtpgo.service mtpgo_openrc
sum=$(sha256sum "$work/$archive"); sum=${sum%% *}
printf '%s  %s\n' "$sum" "$archive" > "$work/manifest"
curl() {
    local dest="" url=""
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == -o ]]; then dest=$2; shift 2
        else url=$1; shift; fi
    done
    if [[ "$url" == */SHA256SUMS.txt ]]; then cp "$work/manifest" "$dest"
    else cp "$work/$archive" "$dest"; fi
}
mkdir "$work/download-good"
fetch_release v1 "$work/download-good"
assert_equal "$(<"$work/download-good/unpacked/mtpgo")" binary
printf '%064d  %s\n' 0 "$archive" > "$work/manifest"
mkdir "$work/download-bad"
if fetch_release v1 "$work/download-bad"; then printf '%s\n' 'accepted bad checksum'; exit 1; fi
[[ ! -d "$work/download-bad/unpacked" ]]
# A checksum-valid archive with a symlink must still be rejected.
rm "$work/fixture/mtpgo"
ln -s /etc/passwd "$work/fixture/mtpgo"
tar -czf "$work/$archive" -C "$work/fixture" mtpgo config.ini mtpgo.service mtpgo_openrc
sum=$(sha256sum "$work/$archive"); sum=${sum%% *}
printf '%s  %s\n' "$sum" "$archive" > "$work/manifest"
mkdir "$work/download-link"
if fetch_release v1 "$work/download-link"; then printf '%s\n' 'accepted symlink'; exit 1; fi
[[ ! -d "$work/download-link/unpacked" ]]

# Update uses fixture executables outside downloaded data and never system paths.
unset -f curl
install_base() { release=debian; }
check_arch() { arch=arm64; }
latest_release() { printf '%s\n' v2; }
setup_service_user() { return 0; }
chown() { return 0; }
sleep() { return 0; }
systemctl() { return 0; }
service_path() { printf '%s\n' "$mtp_dir/service"; }
enable_mtproxy() { return 0; }
new_staging_dir() { mktemp -d "$work/stage.XXXXXXXX"; }
fetch_release() {
    local dest="$2"
    [[ "$dest" != "$mtp_dir" && "$dest" != "$mtp_dir/"* ]]
    printf '%s\n' "$dest" > "$mtp_dir/stage-path"
    printf '%s\n' downloaded >> "$mtp_dir/events"
    [[ "$scenario" != download-failure ]] || return 1
    mkdir "$dest/unpacked"
    cp "$work/new-program" "$dest/unpacked/mtpgo"
    printf 'SECRET = packaged-default\nPORT = 8443\n' > "$dest/unpacked/config.ini"
    printf new-service > "$dest/unpacked/mtpgo.service"
}
install_service_files() {
    cp "$1/mtpgo.service" "$(service_path)"
    if [[ "$scenario" == service-failure || "$scenario" == rollback-failure ]]; then
        [[ "$scenario" != rollback-failure ]] || touch "$mtp_dir/running"
        return 1
    fi
    if [[ "$scenario" == interrupted ]]; then exit 143; fi
}
check_service_status() { [[ -f "$mtp_dir/running" ]]; }
stop_mtproxy() {
    printf stop >> "$mtp_dir/actions"
    printf '%s\n' stopped >> "$mtp_dir/events"
    [[ "$scenario" != stop-failure ]] || return 1
    if [[ "$scenario" == stop-reported-failure ]]; then rm -f "$mtp_dir/running"; return 1; fi
    if [[ "$scenario" == rollback-failure ]] && grep -q new-version "$mtp_file"; then return 1; fi
    rm -f "$mtp_dir/running"
}
start_mtproxy() {
    printf '%s\n' started >> "$mtp_dir/events"
    if [[ "$scenario" == startup-failure ]] && grep -q new-version "$mtp_file"; then return 1; fi
    touch "$mtp_dir/running"
}
prepare_update() {
    scenario=$1
    mtp_dir="$work/$scenario";mkdir "$mtp_dir"
    mtp_file="$mtp_dir/mtpgo";mtp_conf="$mtp_dir/config.ini";mtp_info="$mtp_dir/mtp_info"
    printf '#!/bin/bash\n# old-version\nexit 0\n' > "$mtp_file";chmod +x "$mtp_file"
    printf 'SECRET = user-secret\nPORT = 54321\n' > "$mtp_conf"
    printf old-info > "$mtp_info";printf old-service > "$mtp_dir/service"
    printf v1 > "$mtp_dir/version";touch "$mtp_dir/running"
    printf '#!/bin/bash\n# new-version\nexit %s\n' "$2" > "$work/new-program";chmod +x "$work/new-program"
}
prepare_update success 0
Update
assert_equal "$(ini_get "$mtp_conf" SECRET)" user-secret
assert_equal "$(ini_get "$mtp_conf" PORT)" 54321
assert_equal "$(<"$mtp_info")" old-info
assert_equal "$(<"$mtp_dir/version")" v2
grep -q new-version "$mtp_file"

prepare_update config-failure 1
if Update; then printf '%s\n' 'accepted invalid config'; exit 1; fi
[[ ! -f "$mtp_dir/actions" && -f "$mtp_dir/running" ]]
grep -q old-version "$mtp_file"
assert_equal "$(<"$mtp_dir/version")" v1

prepare_update startup-failure 0
if Update; then printf '%s\n' 'failed startup not detected'; exit 1; fi
grep -q old-version "$mtp_file"
assert_equal "$(<"$mtp_dir/service")" old-service
assert_equal "$(ini_get "$mtp_conf" SECRET)" user-secret
assert_equal "$(<"$mtp_dir/version")" v1
[[ -f "$mtp_dir/running" ]]
[[ ! -d "$(<"$mtp_dir/stage-path")" ]]

# All ordinary failures clean staging, preserve config/info/version, and keep
# the original running service (or restore it if files were already changed).
for failure in download-failure service-failure stop-failure stop-reported-failure interrupted; do
    prepare_update "$failure" 0
    if Update; then printf 'failure not detected: %s\n' "$failure"; exit 1; fi
    grep -q old-version "$mtp_file"
    assert_equal "$(<"$mtp_dir/service")" old-service
    assert_equal "$(ini_get "$mtp_conf" SECRET)" user-secret
    assert_equal "$(<"$mtp_info")" old-info
    assert_equal "$(<"$mtp_dir/version")" v1
    [[ -f "$mtp_dir/running" && ! -d "$(<"$mtp_dir/stage-path")" ]]
    if [[ "$failure" == download-failure ]]; then [[ ! -f "$mtp_dir/actions" ]]; fi
 done

prepare_update initially-stopped 0
rm "$mtp_dir/running"
Update
[[ ! -f "$mtp_dir/running" && ! -f "$mtp_dir/actions" ]]
assert_equal "$(<"$mtp_dir/version")" v2
assert_equal "$(ini_get "$mtp_conf" SECRET)" user-secret
[[ ! -d "$(<"$mtp_dir/stage-path")" ]]

prepare_update already-current 0
printf v2 > "$mtp_dir/version"
Update
[[ ! -f "$mtp_dir/stage-path" && ! -f "$mtp_dir/actions" ]]
grep -q old-version "$mtp_file"

prepare_update rollback-failure 0
if Update; then printf '%s\n' 'rollback failure not reported'; exit 1; fi
stage=$(<"$mtp_dir/stage-path")
[[ -f "$stage/backup/mtpgo" && -f "$stage/backup/config.ini" && -f "$stage/backup/version" ]]
grep -q old-version "$stage/backup/mtpgo"
assert_equal "$(<"$mtp_dir/version")" v1

# Initial installation exercises the real example-style prompts while every
# host-level operation remains mocked. Ownership flags are only stripped here.
install() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
    done
    command install "${args[@]}"
}
get_public_ip() { IPv4=192.0.2.1; IPv6=2001:db8::1; }
Start() { touch "$mtp_dir/running"; }
prepare_install() {
    scenario="$1"
    mtp_dir="$work/$scenario"; mkdir "$mtp_dir"
    mtp_file="$mtp_dir/mtpgo"; mtp_conf="$mtp_dir/config.ini"; mtp_info="$mtp_dir/mtp_info"
    # Preserve $1 for the generated fixture's runtime argument, not this function.
    # shellcheck disable=SC2016
    printf '#!/bin/bash\ncase "$1" in -s) printf "%%s\\n" 6dcaf91a861ee45c5a218c465d52a307;; -check) exit %s;; esac\n' "$2" > "$work/new-program"
    chmod +x "$work/new-program"
}
prepare_install install-success 0
Install <<< $'12345\n3\nexample.com\n'
assert_equal "$(ini_get "$mtp_conf" PORT)" 12345
assert_equal "$(ini_get "$mtp_conf" MODES_TLS)" true
assert_equal "$(ini_get "$mtp_conf" TLS_DOMAIN)" example.com
assert_equal "$(ini_get "$mtp_info" IPv4)" 192.0.2.1
[[ -f "$mtp_dir/running" && ! -d "$(<"$mtp_dir/stage-path")" ]]
[[ ! -f "$mtp_dir/mtpgo-linux-arm64.tar.gz" ]]

prepare_install install-config-failure 1
if Install <<< $'12345\n2\n'; then printf '%s\n' 'invalid install config accepted'; exit 1; fi
[[ ! -e "$mtp_file" && ! -e "$mtp_conf" && ! -d "$(<"$mtp_dir/stage-path")" ]]

# Link display uses the configured port/secret, not legacy mtp_info values.
# jq is stubbed for this IPv4-only fixture; no extra test dependency is needed.
jq() { local value; IFS= read -r value || true; printf '%s\n' "$value"; }
mtp_dir="$work/install-success"
mtp_file="$mtp_dir/mtpgo"; mtp_conf="$mtp_dir/config.ini"; mtp_info="$mtp_dir/mtp_info"
ini_set "$mtp_conf" MY_DOMAIN proxy.example.com
ini_set "$mtp_conf" SECRET 6dcaf91a861ee45c5a218c465d52a307
ini_set "$mtp_conf" MODES_CLASSIC false
ini_set "$mtp_conf" MODES_SECURE true
ini_set "$mtp_conf" MODES_TLS false
printf 'IPv4=192.0.2.1\nPORT=1\nSECURE=stale\n' > "$mtp_info"
view_output=$(View </dev/null)
[[ "$view_output" == *'server=proxy.example.com&port=12345&secret=dd6dcaf91a861ee45c5a218c465d52a307'* && "$view_output" != *'secret=stale'* ]]

# The restored example menu keeps all ten choices and returns to the caller,
# rather than recursively invoking itself or exiting when sourced.
menu_status=0
menu_output=$(menu <<< 0) || menu_status=$?
assert_equal "$menu_status" 2
[[ "$menu_output" == *'MTProxy 一键脚本'* && "$menu_output" == *'查看 MTProxy链接'* && "$menu_output" == *'更新 MTProxy'* ]]
printf '%s\n' 'Installer regression tests: PASS'
