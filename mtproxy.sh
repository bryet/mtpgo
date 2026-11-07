#!/bin/bash
# Installation needs root; the proxy itself runs as the unprivileged mtpgo user.
# Sourcing this file only defines functions, for isolated regression tests.

GITHUB_REPO="bryet/mtpgo"

Red="\033[31m"
Green="\033[32m"
Yellow="\033[33m"
Nc="\033[0m"
Red_globa="\033[41;37m"
Green_globa="\033[42;37m"
Info="${Green}[信息]${Nc}"
Error="${Red}[错误]${Nc}"
Tip="${Yellow}[提示]${Nc}"

mtp_dir="/var/mtpgo"
mtp_file="${mtp_dir}/mtpgo"
mtp_conf="${mtp_dir}/config.ini"
mtp_info="${mtp_dir}/mtp_info"

check_root() {
    if [[ $(id -u) != 0 ]]; then
        printf '%b\n' "${Error} 请使用 root 或 ${Green_globa}sudo -i${Nc} 运行安装管理脚本。" >&2
        return 1
    fi
}

check_arch() {
    case "$(uname -m)" in
        x86_64|x64|amd64) arch=amd64 ;;
        i?86|x86) arch=386 ;;
        aarch64|arm64|armv8*) arch=arm64 ;;
        armv7*) arch=armv7 ;;
        armv6*) arch=armv6 ;;
        armv5*) arch=armv5 ;;
        s390x) arch=s390x ;;
        *) printf '%s\n' '不支持的 CPU 架构' >&2; return 1 ;;
    esac
}

check_release() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
    else
        printf '%s\n' '无法识别操作系统' >&2; return 1
    fi
    release=$ID
    case "$release" in
        ol) release=oracle ;;
        debian|ubuntu|kali|alpine|centos|fedora|almalinux|rocky) ;;
        *) printf '不支持的操作系统: %s\n' "$release" >&2; return 1 ;;
    esac
}

install_base() {
    check_release || return 1
    local missing=false cmd
    for cmd in curl tar jq sha256sum shuf od install; do
        command -v "$cmd" >/dev/null 2>&1 || missing=true
    done
    if [[ "$release" != alpine ]]; then command -v useradd >/dev/null 2>&1 || missing=true; fi
    [[ -s /etc/ssl/certs/ca-certificates.crt || -s /etc/pki/tls/certs/ca-bundle.crt ]] || missing=true
    if [[ "$missing" == true ]]; then
        case "$release" in
            debian|ubuntu|kali)
                apt-get update && apt-get install -y curl tar jq coreutils ca-certificates passwd || return 1 ;;
            alpine)
                apk add curl tar jq coreutils ca-certificates || return 1 ;;
            *) dnf install -y curl tar jq coreutils ca-certificates shadow-utils || return 1 ;;
        esac
    fi
    # mtpgo -s replaces openssl; od replaces xxd. No grep -P/BusyBox mismatch.
}

check_installed_status() {
    [[ -x "$mtp_file" && -f "$mtp_conf" ]] || { printf '%s\n' 'MTProxy 尚未安装' >&2; return 1; }
}
check_service_status() {
    if [[ "$release" == alpine ]]; then rc-service mtpgo status >/dev/null 2>&1
    else systemctl is-active --quiet mtpgo.service; fi
}
start_mtproxy() {
    if [[ "$release" == alpine ]]; then rc-service mtpgo start
    else systemctl start mtpgo.service; fi
}
stop_mtproxy() {
    if [[ "$release" == alpine ]]; then rc-service mtpgo stop
    else systemctl stop mtpgo.service; fi
}
enable_mtproxy() {
    if [[ "$release" == alpine ]]; then rc-update add mtpgo default
    else systemctl enable mtpgo.service; fi
}
disable_mtproxy() {
    if [[ "$release" == alpine ]]; then rc-update del mtpgo default
    else systemctl disable mtpgo.service; fi
}
service_path() {
    if [[ "$release" == alpine ]]; then printf '%s\n' /etc/init.d/mtpgo
    else printf '%s\n' /lib/systemd/system/mtpgo.service; fi
}

latest_release() {
    local version
    version=$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | jq -er .tag_name) || return 1
    [[ "$version" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$ ]] || return 1
    printf '%s\n' "$version"
}

new_staging_dir() {
    # Explicit /tmp path: TMPDIR and the caller's working directory must not
    # redirect downloads into the installation tree. mktemp creates mode 0700.
    mktemp -d /tmp/mtpgo.XXXXXXXX
}

# dest must be a newly created, empty directory. Reject links, special files,
# duplicate entries and unexpected paths before extraction into a second empty
# directory. The checksum manifest is retrieved over verified HTTPS as well.
fetch_release() {
    local version="$1" dest="$2" archive="mtpgo-linux-${arch}.tar.gz"
    local base="https://github.com/${GITHUB_REPO}/releases/download/${version}"
    local expected actual listing entry count=0
    curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 120 -o "$dest/$archive" "$base/$archive" || return 1
    curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 30 -o "$dest/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || return 1
    expected=$(awk -v file="$archive" '$2 == file { print $1 }' "$dest/SHA256SUMS.txt")
    [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || { printf '%s\n' '缺少或重复的 SHA256 校验值' >&2; return 1; }
    actual=$(sha256sum "$dest/$archive") || return 1
    actual=${actual%% *}
    [[ "${actual,,}" == "${expected,,}" ]] || { printf '%s\n' 'SHA256 校验失败' >&2; return 1; }
    listing=$(tar -tzf "$dest/$archive") || return 1
    while IFS= read -r entry; do
        case "$entry" in mtpgo|mtpgo.service|mtpgo_openrc|config.ini) ;; *) printf '不允许的归档路径: %s\n' "$entry" >&2; return 1 ;; esac
        ((count+=1))
    done <<< "$listing"
    [[ "$count" == 4 && $(printf '%s\n' "$listing" | sort -u | wc -l) == 4 ]] || return 1
    listing=$(tar -tvzf "$dest/$archive") || return 1
    while IFS= read -r entry; do
        [[ "$entry" == -* ]] || { printf '%s\n' '归档包含非普通文件' >&2; return 1; }
    done <<< "$listing"
    mkdir "$dest/unpacked" || return 1
    tar --no-same-owner --no-same-permissions -xzf "$dest/$archive" -C "$dest/unpacked" || return 1
    chmod 0755 "$dest/unpacked/mtpgo" || return 1
}

setup_service_user() {
    if ! id mtpgo >/dev/null 2>&1; then
        if [[ "$release" == alpine ]]; then
            addgroup -S mtpgo && adduser -S -D -H -h /var/mtpgo -s /sbin/nologin -G mtpgo mtpgo || return 1
        else
            useradd --system --user-group --no-create-home --home-dir /var/mtpgo --shell /usr/sbin/nologin mtpgo || return 1
        fi
    fi
    [[ $(id -u mtpgo) != 0 ]] || return 1
    install -d -m 0750 -o root -g mtpgo "$mtp_dir" || return 1
    install -d -m 0700 -o mtpgo -g mtpgo /var/log/mtpgo /run/mtpgo || return 1
}
install_service_files() {
    local src="$1"
    if [[ "$release" == alpine ]]; then
        install -m 0755 "$src/mtpgo_openrc" "$(service_path)" || return 1
    else
        install -m 0644 "$src/mtpgo.service" "$(service_path)" || return 1
        systemctl daemon-reload || return 1
    fi
}

# Edit a candidate file only. Production configuration is replaced after all
# prompts and mtpgo -check succeed; interruption cannot leave half an edit.
ini_set() {
    local file="$1" key="$2" value="$3" tmp
    tmp=$(mktemp "${file}.XXXXXX") || return 1
    if ! awk -v key="$key" -v value="$value" '
        BEGIN { done=0 }
        $0 ~ "^[[:space:]#;]*" key "[[:space:]]*=" {
            if (!done) print key " = " value
            done=1; next
        }
        {print}
        END {if (!done) print key " = " value}
    ' "$file" > "$tmp"; then rm -f -- "$tmp"; return 1; fi
    mv -f -- "$tmp" "$file"
}
ini_get() {
    awk -v key="$2" '
        $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*[#;].*$/, "")
            sub(/[[:space:]]*$/, ""); gsub(/^["\047]|["\047]$/, ""); print; exit
        }
    ' "$1"
}

Set_port() {
    local file="${1:-$mtp_conf}" port
    while true; do
        printf '%b\n' "${Tip} 请输入 MTProxy 端口 [10000-65535]"
        read -er -p '(默认：随机生成):' port || return 1
        [[ -n "$port" ]] || port=$(shuf -i 10000-65535 -n 1)
        if [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 10000 && 10#$port <= 65535)); then
            port=$((10#$port))
            ini_set "$file" PORT "$port" || return 1
            printf '\n========================\n  端口 : %b\n========================\n\n' "${Red_globa} ${port} ${Nc}"
            return 0
        fi
        printf '%s\n' '输入错误，请输入正确的端口。'
    done
}
Set_passwd() {
    local file="${1:-$mtp_conf}" binary="${2:-$mtp_file}" mode secret domain name encoded
    printf '%b\n' "${Tip} 请选择密匙模式：" \
        "  ${Green}1.${Nc} 普通模式 (32位十六进制字符)" \
        "  ${Green}2.${Nc} 安全模式 (dd+32位十六进制字符)" \
        "  ${Green}3.${Nc} TLS 模式 (ee+32位十六进制字符+TLS域名)${Red_globa}[默认]${Nc}"
    while true; do
        read -er -p '(请输入数字 1-3，默认：3):' mode || return 1
        mode=${mode:-3}
        [[ "$mode" =~ ^[123]$ ]] && break
        printf '%b\n' "${Error} 请输入正确数字 [1-3]"
    done
    domain=$(ini_get "$file" TLS_DOMAIN)
    domain=${domain:-itunes.apple.com}
    if [[ "$mode" == 3 ]]; then
        printf '%b\n' "${Tip} 请输入 TLS 伪装域名"
        read -er -p '(默认：itunes.apple.com):' domain || return 1
        domain=${domain:-itunes.apple.com}
        [[ "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ && ${#domain} -le 253 ]] || { printf '%b\n' "${Error} 域名无效" >&2; return 1; }
    fi
    secret=$("$binary" -s) || return 1
    [[ "$secret" =~ ^[0-9a-f]{32}$ ]] || return 1
    ini_set "$file" SECRET "$secret" || return 1
    ini_set "$file" MODES_CLASSIC "$([[ "$mode" == 1 ]] && printf true || printf false)" || return 1
    ini_set "$file" MODES_SECURE "$([[ "$mode" == 2 ]] && printf true || printf false)" || return 1
    ini_set "$file" MODES_TLS "$([[ "$mode" == 3 ]] && printf true || printf false)" || return 1
    encoded=$secret
    case "$mode" in
        1) name=普通模式 ;;
        2) name=安全模式; encoded="dd$secret" ;;
        3)
            name=TLS模式
            ini_set "$file" TLS_DOMAIN "$domain" || return 1
            encoded="ee${secret}$(printf '%s' "$domain" | od -An -v -tx1 | tr -d ' \n')"
            ;;
    esac
    printf '\n========================\n  模式 : %b\n' "${Green}${name}${Nc}"
    [[ "$mode" != 3 ]] || printf '  域名 : %b\n' "${Green}${domain}${Nc}"
    printf '  密匙 : %b\n========================\n\n' "${Red_globa}${encoded}${Nc}"
}
Set_tag() {
    local file="${1:-$mtp_conf}" tag
    printf '%b\n' "${Tip} 请输入 MTProxy TAG（32位十六进制字符，从 @MTProxybot 获取；不清楚请留空回车）"
    read -er -p '(默认：回车跳过):' tag || return 1
    [[ -z "$tag" || "$tag" =~ ^[0-9a-fA-F]{32}$ ]] || { printf '%b\n' "${Error} TAG 无效" >&2; return 1; }
    ini_set "$file" AD_TAG "$tag" || return 1
    if [[ -n "$tag" ]]; then printf '\n========================\n  TAG : %b\n========================\n' "${Red_globa} ${tag} ${Nc}"; fi
    return 0
}

get_public_ip() {
    local api value
    IPv4=""; IPv6=""
    for api in https://api.ipify.org https://ident.me https://icanhazip.com; do
        if [[ -z "$IPv4" ]]; then
            value=$(curl -fsS4 --connect-timeout 3 --max-time 5 "$api" 2>/dev/null) || value=""
            [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && IPv4="$value"
        fi
        if [[ -z "$IPv6" ]]; then
            value=$(curl -fsS6 --connect-timeout 3 --max-time 5 "$api" 2>/dev/null) || value=""
            [[ "$value" == *:* && "$value" =~ ^[0-9a-fA-F:]+$ ]] && IPv6="$value"
        fi
        [[ -n "$IPv4" && -n "$IPv6" ]] && break
    done
    return 0
}

# Keep the example's Download entrypoint; both install and update share exactly
# the same verified download path and never change into the installation tree.
Download() {
    printf '%b\n' "${Info} 开始下载 mtpgo ${1}，临时目录：${2}"
    fetch_release "$1" "$2"
}

Install() (
    umask 077
    [[ ! -e "$mtp_file" ]] || { printf '%b\n' "${Error} 检测到 MTProxy 已安装！"; return 1; }
    install_base && check_arch || return 1
    local version stage
    version=$(latest_release) || return 1
    stage=$(new_staging_dir) || return 1
    trap 'rm -rf -- "$stage"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    Download "$version" "$stage" || return 1
    local candidate="$stage/candidate.ini"
    cp "$stage/unpacked/config.ini" "$candidate" || return 1
    printf '%b\n' "${Tip} 开始设置用户配置……"
    Set_port "$candidate" && Set_passwd "$candidate" "$stage/unpacked/mtpgo" && Set_tag "$candidate" || return 1
    "$stage/unpacked/mtpgo" -check -c "$candidate" || return 1
    setup_service_user || return 1
    install -m 0755 "$stage/unpacked/mtpgo" "$mtp_file" &&
    install -m 0640 -o root -g mtpgo "$candidate" "$mtp_conf" &&
    install_service_files "$stage/unpacked" || return 1
    printf '%s\n' "$version" > "$mtp_dir/version" || return 1
    get_public_ip
    printf 'IPv4=%s\nIPv6=%s\n' "$IPv4" "$IPv6" > "$mtp_info" || return 1
    printf '%b\n' "${Info} 所有步骤执行完毕，开始启动……"
    Start
)

# Replacement stays on the target filesystem for an atomic rename. This also
# allows rollback without overwriting a still-open executable inode.
atomic_install() {
    local src="$1" target="$2" mode="$3" candidate
    candidate=$(mktemp "${target}.XXXXXX") || return 1
    if ! install -m "$mode" "$src" "$candidate" || ! mv -f -- "$candidate" "$target"; then
        rm -f -- "$candidate"
        return 1
    fi
}

# On failure, restore the prior service definition and metadata before restarting
# the old service. A failed rollback retains its backup and reports the location.
rollback_update() {
    local stage="$1" service="$2" active="$3"
    printf '%b\n' "${Error} 更新失败，恢复旧程序和服务配置……" >&2
    if check_service_status; then stop_mtproxy || return 1; fi
    atomic_install "$stage/backup/mtpgo" "$mtp_file" 0755 || return 1
    cp -p "$stage/backup/config.ini" "$mtp_conf" || return 1
    if [[ -f "$stage/backup/service" ]]; then
        cp -p "$stage/backup/service" "$service" || return 1
    else
        rm -f -- "$service" || return 1
    fi
    if [[ -f "$stage/backup/version" ]]; then
        cp -p "$stage/backup/version" "$mtp_dir/version" || return 1
    else
        rm -f -- "$mtp_dir/version" || return 1
    fi
    if [[ "$release" != alpine ]]; then systemctl daemon-reload || return 1; fi
    if [[ "$active" == true ]]; then
        start_mtproxy && sleep 2 && check_service_status || return 1
    fi
    return 0
}

finish_update() {
    local status="$1" stage="$2" rollback_needed="$3" service="$4" active="$5"
    trap - EXIT INT TERM
    if [[ "$rollback_needed" == true ]]; then
        if ! rollback_update "$stage" "$service" "$active"; then
            printf '%b\n' "${Error} 回滚未完成，备份保留在：${stage}/backup" >&2
            exit 1
        fi
    fi
    rm -rf -- "$stage"
    exit "$status"
}

Update() (
    umask 077
    check_installed_status && install_base && check_arch || return 1
    printf '%b\n' "${Info} 开始更新 mtpgo 程序……"
    local version current="" stage active=false service="" rollback_needed=false
    version=$(latest_release) || return 1
    [[ -f "$mtp_dir/version" ]] && current=$(<"$mtp_dir/version")
    if [[ "$current" == "$version" ]]; then
        printf '%b\n' "${Info} mtpgo 已经是最新版本：${version}"
        return 0
    fi
    printf '%b\n' "${Info} 发现新版本：${version}，当前版本：${current:-未知}"
    stage=$(new_staging_dir) || return 1
    trap 'finish_update "$?" "$stage" "$rollback_needed" "$service" "$active"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Fetch, verify and validate before stopping the existing service. Never
    # copy the archive's config.ini or generate new mtp_info during an upgrade.
    Download "$version" "$stage" || return 1
    if ! "$stage/unpacked/mtpgo" -check -c "$mtp_conf"; then
        printf '%b\n' "${Error} 新程序拒绝当前配置；旧服务未停止，请先修正配置。" >&2
        return 1
    fi
    service=$(service_path)
    mkdir "$stage/backup" || return 1
    cp -p "$mtp_file" "$stage/backup/mtpgo" && cp -p "$mtp_conf" "$stage/backup/config.ini" || return 1
    if [[ -f "$service" ]]; then cp -p "$service" "$stage/backup/service" || return 1; fi
    if [[ -f "$mtp_dir/version" ]]; then cp -p "$mtp_dir/version" "$stage/backup/version" || return 1; fi
    if check_service_status; then
        active=true
        rollback_needed=true
        printf '%b\n' "${Info} 下载和校验完成，停止当前服务……"
        if ! stop_mtproxy; then
            # A failed stop can still have stopped the daemon. Roll back/restart
            # in that case; otherwise leave the still-running version untouched.
            if check_service_status; then rollback_needed=false; fi
            return 1
        fi
        # If a manager returned success without stopping, leave files untouched.
        if check_service_status; then
            rollback_needed=false
            printf '%b\n' "${Error} 服务未停止，取消更新。" >&2
            return 1
        fi
    fi
    rollback_needed=true
    setup_service_user && chown root:mtpgo "$mtp_conf" && chmod 0640 "$mtp_conf" &&
        atomic_install "$stage/unpacked/mtpgo" "$mtp_file" 0755 &&
        install_service_files "$stage/unpacked" || return 1
    if [[ "$active" == true ]]; then
        start_mtproxy && sleep 2 && check_service_status || return 1
    fi
    # Write the version only after install/startup succeeds; rename metadata on
    # the same filesystem, and rollback if either operation fails.
    local version_file
    version_file=$(mktemp "$mtp_dir/version.XXXXXXXX") || return 1
    if ! printf '%s\n' "$version" > "$version_file" || ! mv -f -- "$version_file" "$mtp_dir/version"; then
        rm -f -- "$version_file"
        return 1
    fi
    rollback_needed=false
    printf '%b\n' "${Info} mtpgo 更新完成！配置和链接信息保持不变。"
    if [[ "$active" == false ]]; then printf '%b\n' "${Info} 服务原本已停止，更新后仍保持停止。"; fi
    return 0
)

Set() (
    check_installed_status || return 1
    local choice candidate
    printf '%b\n' "${Tip} 开始设置用户配置……" \
        "你要修改什么？" \
        "${Green} 1.${Nc} 修改端口配置" \
        "${Green} 2.${Nc} 修改密匙配置" \
        "${Green} 3.${Nc} 修改 TAG 配置" \
        "${Green} 4.${Nc} 修改全部配置"
    read -er -p '(默认：取消):' choice || return 1
    [[ -n "$choice" ]] || { printf '%b\n' "${Tip} 已取消。"; return 0; }
    candidate=$(mktemp "${mtp_conf}.XXXXXX") || return 1
    trap 'rm -f -- "$candidate"' EXIT
    cp "$mtp_conf" "$candidate" || return 1
    case "$choice" in
        1) Set_port "$candidate" || return 1 ;;
        2) Set_passwd "$candidate" "$mtp_file" || return 1 ;;
        3) Set_tag "$candidate" || return 1 ;;
        4) Set_port "$candidate" && Set_passwd "$candidate" "$mtp_file" && Set_tag "$candidate" || return 1 ;;
        *) return 1 ;;
    esac
    "$mtp_file" -check -c "$candidate" || return 1
    chown root:mtpgo "$candidate" && chmod 0640 "$candidate" && mv -f "$candidate" "$mtp_conf" || return 1
    Restart
)

Start() {
    check_installed_status && "$mtp_file" -check -c "$mtp_conf" || return 1
    if check_service_status; then
        printf '%b\n' "${Info} MTProxy 正在运行。"
        View
        return
    fi
    if ! { start_mtproxy && sleep 2 && check_service_status && enable_mtproxy; }; then
        printf '%b\n' "${Error} MTProxy 启动失败，请检查日志！" >&2
        return 1
    fi
    View
}
Stop() {
    check_installed_status || return 1
    if ! check_service_status; then printf '%b\n' "${Info} MTProxy 已停止。"; return 0; fi
    stop_mtproxy && sleep 2 || return 1
    if check_service_status; then printf '%b\n' "${Error} MTProxy 停止失败。" >&2; return 1; fi
    printf '%b\n' "${Info} MTProxy 已停止。"
}
Restart() {
    check_installed_status && "$mtp_file" -check -c "$mtp_conf" || return 1
    if check_service_status; then stop_mtproxy || return 1; fi
    if ! { start_mtproxy && sleep 2 && check_service_status; }; then
        printf '%b\n' "${Error} MTProxy 重启失败，请检查日志！" >&2
        return 1
    fi
    View
}

Read_config() {
    # Use actual configuration, never the stale PORT/SECURE/TAG saved by an
    # older script in mtp_info. Public addresses remain in that metadata file.
    IPv4=""; IPv6=""
    if [[ -f "$mtp_info" ]]; then
        IPv4=$(ini_get "$mtp_info" IPv4)
        IPv6=$(ini_get "$mtp_info" IPv6)
    fi
    PORT=$(ini_get "$mtp_conf" PORT); PORT=${PORT:-3256}
    TAG=$(ini_get "$mtp_conf" AD_TAG)
}

View() {
    check_installed_status || return 1
    Read_config
    [[ ! -t 1 ]] || clear
    printf '\nMtproto Proxy 用户配置：\n————————————————\n'
    local port secrets domain host secret encoded mode value
    port=$PORT
    secrets=$(ini_get "$mtp_conf" SECRET)
    domain=$(ini_get "$mtp_conf" TLS_DOMAIN); domain=${domain:-www.google.com}
    host=$(ini_get "$mtp_conf" MY_DOMAIN)
    local hosts=()
    if [[ -n "$host" ]]; then hosts+=("$host")
    else
        [[ -z "$IPv4" ]] || hosts+=("$IPv4")
        [[ -z "$IPv6" ]] || hosts+=("$IPv6")
    fi
    [[ ${#hosts[@]} -gt 0 ]] || { printf '%b\n' "${Tip} 无公网 IP，请配置 MY_DOMAIN 或重新探测 IP。"; return 1; }
    for host in "${hosts[@]}"; do printf ' 地址\t: %b\n' "${Green}${host}${Nc}"; done
    printf ' 端口\t: %b\n' "${Green}${port}${Nc}"
    [[ -z "$TAG" ]] || printf ' TAG\t: %b\n' "${Green}${TAG}${Nc}"
    local secret_list=()
    IFS=',' read -r -a secret_list <<< "$secrets"
    for secret in "${secret_list[@]}"; do
        secret=${secret//[[:space:]]/}
        for mode in CLASSIC SECURE TLS; do
            value=$(ini_get "$mtp_conf" "MODES_$mode"); value=${value:-true}
            [[ "${value,,}" == true || "$value" == 1 || "${value,,}" == yes ]] || continue
            encoded=$secret
            [[ "$mode" != SECURE ]] || encoded="dd$secret"
            [[ "$mode" != TLS ]] || encoded="ee${secret}$(printf '%s' "$domain" | od -An -v -tx1 | tr -d ' \n')"
            printf ' 密匙\t: %b\n' "${Green}${encoded}${Nc}"
            for host in "${hosts[@]}"; do
                host=$(printf '%s' "$host" | jq -sRr @uri)
                printf '%b\n' "${Red}https://t.me/proxy?server=${host}&port=${port}&secret=${encoded}${Nc}" \
                    "${Red}tg://proxy?server=${host}&port=${port}&secret=${encoded}${Nc}"
            done
        done
    done
    printf '\n%b\n' "${Tip} ee 表示 TLS 伪装模式；dd 表示安全混淆模式。"
    backmenu
}
View_Log() {
    check_installed_status || return 1
    if [[ -f /var/log/mtpgo/log_mtpgo ]]; then tail -f /var/log/mtpgo/log_mtpgo
    elif [[ "$release" != alpine ]]; then journalctl -u mtpgo -f
    else printf '%s\n' '暂无日志'; fi
}
Uninstall() {
    check_installed_status || return 1
    local answer
    read -r -p '确定卸载并删除 /var/mtpgo 的配置？[y/N]: ' answer || return 1
    [[ "$answer" == y || "$answer" == Y ]] || return 0
    if check_service_status; then stop_mtproxy || return 1; fi
    disable_mtproxy || return 1
    rm -f -- "$(service_path)"
    [[ "$release" == alpine ]] || systemctl daemon-reload
    rm -rf -- "$mtp_dir"
    printf '%s\n' '已卸载；专用账户和 /var/log/mtpgo 日志保留。'
}
Esc_Shell() { exit 0; }
backmenu() {
    # Keep the example's return prompt without recursively nesting menu calls.
    # Noninteractive tests and sourced use never wait for terminal input.
    [[ -t 0 ]] || return 0
    local answer
    printf '\n'
    read -r -p '请输入"y"退出，或按任意键回到主菜单：' answer || return 0
    [[ "$answer" != y ]] || Esc_Shell
    return 0
}
menu() {
    local choice
    [[ ! -t 1 ]] || clear
    printf '%b\n' "${Green}######################################
#          ${Red}MTProxy 一键脚本          ${Green}#
#         作者: ${Yellow}你挺好看啊🍏          ${Green}#
######################################

 0.${Nc} 退出脚本
———————————————————————
${Green} 1.${Nc} 安装 MTProxy
${Green} 2.${Nc} 卸载 MTProxy
${Green} 3.${Nc} 更新 MTProxy
———————————————————————
${Green} 4.${Nc} 启动 MTProxy
${Green} 5.${Nc} 停止 MTProxy
${Green} 6.${Nc} 重启 MTProxy
———————————————————————
${Green} 7.${Nc} 修改 MTProxy配置
${Green} 8.${Nc} 查看 MTProxy链接
${Green} 9.${Nc} 查看 MTProxy日志
———————————————————————"
    if [[ -e "$mtp_file" ]]; then
        if check_service_status; then
            printf '\n%b\n' " 当前状态: ${Green}已安装${Nc} 并 ${Green}已启动${Nc}"
        else
            printf '\n%b\n' " 当前状态: ${Green}已安装${Nc} 但 ${Red}未启动${Nc}"
        fi
    else
        printf '\n%b\n' " 当前状态: ${Red}未安装${Nc}"
    fi
    printf '\n'
    read -er -p ' 请输入数字 [0-9]:' choice || return 2
    case "$choice" in
        0) return 2 ;; 1) Install ;; 2) Uninstall ;; 3) Update ;;
        4) Start ;; 5) Stop ;; 6) Restart ;; 7) Set ;; 8) View ;; 9) View_Log ;;
        *) printf '%b\n' "${Error} 请输入正确数字 [0-9]"; return 1 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    umask 077
    check_root && check_release || exit 1
    while true; do
        menu
        status=$?
        [[ "$status" != 2 ]] || break
        [[ "$status" == 0 ]] || printf '%s\n' '操作未完成，请查看上面的错误。' >&2
    done
fi
