#!/bin/bash

GITHUB_REPO="bryet/mtpgo"

Red="\033[31m"         # 红色
Green="\033[32m"       # 绿色
Yellow="\033[33m"      # 黄色
Blue="\033[34m"        # 蓝色
Nc="\033[0m"           # 重置颜色
Red_globa="\033[41;37m"    # 红底白字
Green_globa="\033[42;37m"  # 绿底白字
Yellow_globa="\033[43;37m" # 黄底白字
Blue_globa="\033[44;37m"   # 蓝底白字
Info="${Green}[信息]${Nc}"
Error="${Red}[错误]${Nc}"
Tip="${Yellow}[提示]${Nc}"

mtp_dir="/var/mtpgo"
mtp_file="${mtp_dir}/mtpgo"
mtp_conf="${mtp_dir}/config.ini"
mtp_info="${mtp_dir}/mtp_info"

# 检查是否为root用户
check_root(){
    if [ "$(id -u)" != "0" ]; then
        echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_globa}sudo -i${Nc} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。"
        exit 1
    fi
}

check_arch(){
    arch=$(arch)
    if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
        arch="amd64"
    elif [[ $arch == i*86 || $arch == "x86" ]]; then
        arch="386"
    elif [[ $arch == "aarch64" || $arch == "arm64" || $arch == armv8* ]]; then
        arch="arm64"
    elif [[ $arch == "armv7l" || $arch == "armv7" || $arch == arm* ]]; then
        arch="armv7"
    elif [[ $arch == "armv6l" || $arch == "armv6" ]]; then
        arch="armv6"
    elif [[ $arch == "armv5l" || $arch == "armv5" ]]; then
        arch="armv5"
    elif [[ $arch == "s390x" ]]; then
        arch="s390x"
    else
        echo -e "${Error} 检测到您的架构不支持，请联系作者！"
        exit 1
    fi

    echo "架构:${Info} ${arch}"
}

check_release(){
    if [[ -e /etc/os-release ]]; then
        . /etc/os-release
        release=$ID
    elif [[ -e /usr/lib/os-release ]]; then
        . /usr/lib/os-release
        release=$ID
    fi
    os_version=$(echo "${VERSION_ID}" | cut -d. -f1,2)

    if [[ "${release}" == "ol" ]]; then
        release=oracle
        os_version=${os_version%.*}
        if [[ ${os_version} -lt 8 ]]; then
            echo -e "${Info} 你的系统是${Red} $release $os_version ${Nc}"
            echo -e "${Error} 请使用${Red} $release 8${Nc} 或更高版本" && exit 1
        fi
    elif [[ "${release}" == "centos" ]]; then
        if [[ ${os_version} -lt 8 ]]; then
            echo -e "${Info} 你的系统是${Red} $release $os_version ${Nc}"
            echo -e "${Error} 请使用${Red} $release 8${Nc} 或更高版本" && exit 1
        fi
    elif [[ "${release}" == "fedora" ]]; then
        if [[ ${os_version} -lt 25 ]]; then
            echo -e "${Info} 你的系统是${Red} $release $os_version ${Nc}"
            echo -e "${Error} 请使用${Red} $release 25${Nc} 或更高版本" && exit 1
        fi
    elif [[ ! "${release}" =~ ^(kali|ubuntu|debian|almalinux|rocky|alpine)$ ]]; then
        echo -e "${Error} 抱歉，此脚本不支持您的操作系统。"
        echo -e "${Info} 请确保您使用的是以下支持的操作系统之一："
        echo -e "-${Red} Ubuntu${Nc} "
        echo -e "-${Red} Debian ${Nc}"
        echo -e "-${Red} CentOS 8+${Nc}"
        echo -e "-${Red} Fedora 25+${Nc}"
        echo -e "-${Red} Kali ${Nc}"
        echo -e "-${Red} AlmaLinux ${Nc}"
        echo -e "-${Red} Rocky Linux ${Nc}"
        echo -e "-${Red} Oracle Linux 8+${Nc}"
        echo -e "-${Red} Alpine Linux${Nc}"
        exit 1
    fi
}

check_pmc(){
    check_release

    case "$release" in
        debian|ubuntu|kali)
            updates="apt update -y"
            installs="apt install -y"
            apps=("wget" "curl" "tar")
            ;;
        almalinux|centos|rocky|oracle|fedora)
            updates="dnf update -y"
            installs="dnf install -y"
            apps=("wget" "curl" "tar")
            ;;
        opensuse-tumbleweed)
            updates="zypper refresh"
            installs="zypper install -y"
            apps=("wget" "curl" "tar")
            ;;
        arch|manjaro|parch)
            updates="pacman -Syu"
            installs="pacman -Syu --noconfirm"
            apps=("wget" "curl" "tar")
            ;;
        alpine)
            updates="apk update"
            installs="apk add"
            apps=("wget" "curl" "tar")
            ;;
        *)
            echo -e "${Error} 不支持的发行版: $release"
            exit 1
            ;;
    esac
}

install_base(){
    check_pmc
    cmds=("wget" "curl" "tar" "tar")
    echo -e "${Info} 你的系统是 ${Red}$release $os_version${Nc}"
    echo

    for i in "${!cmds[@]}"; do
        if ! command -v "${cmds[i]}" &>/dev/null; then
            DEPS+=("${apps[i]}")
        fi
    done
    
    if [ ${#DEPS[@]} -gt 0 ]; then
        echo -e "${Tip} 安装依赖列表：${Green}${DEPS[*]}${Nc} 请稍后..."
        $updates 
        $installs "${DEPS[@]}" 
    else
        echo -e "${Info} 所有依赖已存在，不需要额外安装。"
    fi
}

# 服务状态检查
check_service_status(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-service mtpgo status >/dev/null 2>&1
    else
        systemctl is-active --quiet mtpgo.service
    fi
}

# 检查是否安装MTProxy
check_installed_status(){
    if [[ ! -e "${mtp_file}" ]]; then
        echo -e "${Error} MTProxy 没有安装，请检查 !"
        exit 1
    fi
}

# 启动服务
start_mtproxy(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-service mtpgo start >/dev/null 2>&1
    else
        systemctl start mtpgo.service >/dev/null 2>&1
    fi
}

# 停止服务
stop_mtproxy(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-service mtpgo stop >/dev/null 2>&1
    else
        systemctl stop mtpgo.service >/dev/null 2>&1
    fi
}

# 重启服务
restart_mtproxy(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-service mtpgo restart >/dev/null 2>&1
    else
        systemctl restart mtpgo.service >/dev/null 2>&1
    fi
}

# 启用开机自启
enable_mtproxy(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-update add mtpgo default >/dev/null 2>&1
    else
        systemctl enable mtpgo.service >/dev/null 2>&1
    fi
}

# 禁用开机自启
disable_mtproxy(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-update del mtpgo default >/dev/null 2>&1
    else
        systemctl disable mtpgo.service >/dev/null 2>&1
    fi
}

get_public_ip(){
    InFaces=($(ls /sys/class/net | grep -E '^(eth|ens|enp)'))
    IP_API=(
        "http://ip.gs"
        "http://ip.sb"
        "http://ident.me"
        "http://ifconfig.me"
        "http://api.ipify.org"
        "http://icanhazip.com"
    )

    for iface in "${InFaces[@]}"; do
        for ip_api in "${IP_API[@]}"; do
            IPv4=$(curl -s4 --max-time 2 --interface "$iface" "$ip_api")
            IPv6=$(curl -s6 --max-time 2 --interface "$iface" "$ip_api")

            if [[ -n "$IPv4" || -n "$IPv6" ]]; then # 检查是否获取到IP地址
                break 2 # 获取到任一IP类型停止循环
            fi
        done
    done
}

Download(){
    if [[ ! -e "${mtp_dir}" ]]; then
        mkdir -p "${mtp_dir}"
    fi
    get_public_ip
    cd "${mtp_dir}" || exit 1
    echo -e "${Info} 开始下载/安装..."
    last_version=$(curl -Ls "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "$last_version" ]]; then
        echo -e "${Error} 无法获取 mtpgo 版本，这可能是由于 GitHub API 限制所致，请稍后再试"
        exit 1
    fi
    check_arch
    echo -e "已获取 mtpgo 最新版本: ${last_version}, 开始安装..."
    wget -N --no-check-certificate "https://github.com/${GITHUB_REPO}/releases/download/${last_version}/mtpgo-linux-${arch}.tar.gz"
    if [[ $? -ne 0 ]]; then
        echo -e "${Error} 下载 mtpgo 失败, 请确保您的服务器能够访问GitHub"
        exit 1
    fi
    tar xzf "mtpgo-linux-${arch}.tar.gz"
    rm -f "mtpgo-linux-${arch}.tar.gz"

    # 保存版本信息
    echo "$last_version" > "${mtp_dir}/version"

    if [[ "$release" == "alpine" ]]; then
        mv mtpgo_openrc /etc/init.d/mtpgo
        chmod +x /etc/init.d/mtpgo
    else
        mv mtpgo.service /lib/systemd/system/mtpgo.service
        systemctl daemon-reload
    fi

    cat >"${mtp_info}" <<-EOF
IPv4=$IPv4
IPv6=$IPv6
PORT=8443
SECURE=ee65ae12e414c319fb6aeef9924290825a6974756e65732e6170706c652e636f6d
TAG=
EOF
}

Read_config(){
    IPv4=$(grep 'IPv4=' "${mtp_info}" | cut -d'=' -f2 | grep -P '[.]')
    IPv6=$(grep 'IPv6=' "${mtp_info}" | cut -d'=' -f2 | grep -P '[:]')
    PORT=$(grep 'PORT=' "${mtp_info}" | cut -d'=' -f2)
    SECURE=$(grep 'SECURE=' "${mtp_info}" | cut -d'=' -f2)
    TAG=$(grep 'TAG=' "${mtp_info}" | cut -d'=' -f2)
}

Set_port(){
    while true; do
        echo -e "${Tip} 请输入 MTProxy 端口 [10000-65535]"
        read -e -p "(默认：随机生成):" mtp_port
        [[ -z "${mtp_port}" ]] && mtp_port=$(shuf -i10000-65000 -n1)
        if [[ ${mtp_port} -ge 10000 ]] && [[ ${mtp_port} -le 65535 ]]; then
            echo && echo "========================"
            echo -e "  端口 : ${Red_globa} ${mtp_port} ${Nc}"
            echo "========================" && echo
            break
        else
            echo "输入错误, 请输入正确的端口。"
        fi
    done
    sed -i "s/^#\?PORT.*/PORT = $mtp_port/g" "$mtp_conf"
    sed -i "s/^#\?PORT.*/PORT=$mtp_port/g" "$mtp_info"
}

Set_passwd(){
    echo -e "${Tip} 请选择密匙模式："
    echo -e "  ${Green}1.${Nc} 普通模式 (32位十六进制字符)"
    echo -e "  ${Green}2.${Nc} 安全模式 (dd+32位十六进制字符)"
    echo -e "  ${Green}3.${Nc} TLS 模式 (ee+32位十六进制字符+TLS域名)${Red_globa}[默认]${Nc}"

    read -e -p "(请输入数字 1-3，默认：3):" mtp_mode
    [[ -z "${mtp_mode}" ]] && mtp_mode="3"

    # 生成基础密钥（32位十六进制字符，即16字节）
    mtp_passwd=$(openssl rand -hex 16)
    sed -i "s/^SECRET = .*/SECRET = $mtp_passwd/" "$mtp_conf"

    case "${mtp_mode}" in
        1)
            # 普通模式
            sed -i "s/^MODES_CLASSIC = .*/MODES_CLASSIC = true/" "$mtp_conf"
            sed -i "s/^MODES_SECURE = .*/MODES_SECURE = false/" "$mtp_conf"
            sed -i "s/^MODES_TLS = .*/MODES_TLS = false/" "$mtp_conf"
            mtp_secure="$mtp_passwd"
            sed -i "s/^#\?SECURE.*/SECURE=$mtp_secure/g" "$mtp_info"
            echo && echo "========================"
            echo -e "  模式 : ${Green}普通模式${Nc}"
            echo -e "  密匙 : ${Red_globa}${mtp_secure}${Nc}"
            echo "========================" && echo
            ;;
        2)
            # 安全模式
            sed -i "s/^MODES_CLASSIC = .*/MODES_CLASSIC = false/" "$mtp_conf"
            sed -i "s/^MODES_SECURE = .*/MODES_SECURE = true/" "$mtp_conf"
            sed -i "s/^MODES_TLS = .*/MODES_TLS = false/" "$mtp_conf"
            mtp_secure="dd${mtp_passwd}"
            sed -i "s/^#\?SECURE.*/SECURE=$mtp_secure/g" "$mtp_info"
            echo && echo "========================"
            echo -e "  模式 : ${Green}安全模式${Nc}"
            echo -e "  密匙 : ${Red_globa}${mtp_secure}${Nc}"
            echo "========================" && echo
            ;;
        3)
            # TLS模式
            echo -e "${Tip} 请输入TLS伪装域名 ${Red}(无法使用被墙的域名。)${Nc}"
            read -e -p "(默认：itunes.apple.com):" fake_domain
            [[ -z "${fake_domain}" ]] && fake_domain="itunes.apple.com"
            sed -i "s/^MODES_CLASSIC = .*/MODES_CLASSIC = false/" "$mtp_conf"
            sed -i "s/^MODES_SECURE = .*/MODES_SECURE = false/" "$mtp_conf"
            sed -i "s/^MODES_TLS = .*/MODES_TLS = true/" "$mtp_conf"
            sed -i "s/^TLS_DOMAIN = .*/TLS_DOMAIN = $fake_domain/" "$mtp_conf"
            mtp_secure="ee${mtp_passwd}$(echo -n "$fake_domain" | xxd -ps -c 200)"
            sed -i "s/^#\?SECURE.*/SECURE=$mtp_secure/g" "$mtp_info"
            echo && echo "========================"
            echo -e "  模式 : ${Green}TLS模式${Nc}"
            echo -e "  域名 : ${Green}${fake_domain}${Nc}"
            echo -e "  密匙 : ${Red_globa}${mtp_secure}${Nc}"
            echo "========================" && echo
            ;;
        *)
            echo -e "${Error} 请输入正确数字 [1-3]"
            Set_passwd
            ;;
    esac
}

Set_tag(){
    echo -e "${Tip} 请输入 MTProxy 的 TAG标签（TAG标签必须是32位，TAG标签只有在通过官方机器人 @MTProxybot 分享代理账号后才会获得，不清楚请留空回车）"
    read -e -p "(默认：回车跳过):" mtp_tag
    if [[ -n "${mtp_tag}" ]]; then
        echo && echo "========================"
        echo -e "  TAG : ${Red_globa} ${mtp_tag} ${Nc}"
        echo "========================"
        sed -i 's/^#\?.*AD_TAG.*/AD_TAG = '"$mtp_tag"'/g' "$mtp_conf"
        sed -i "s/^#\?TAG.*/TAG=$mtp_tag/g" "$mtp_info"
    else
        sed -i 's/^#\?.*AD_TAG.*/# AD_TAG = /g' "$mtp_conf"
        sed -i "s/^#\?TAG.*/TAG=/g" "$mtp_info"
    fi
}

Set(){
    echo -e "${Tip} 开始设置 用户配置..."
    check_installed_status
    echo && echo -e "你要修改什么？
${Green} 1.${Nc}  修改 端口配置
${Green} 2.${Nc}  修改 密匙配置
${Green} 3.${Nc}  修改 TAG 配置
${Green} 4.${Nc}  修改 全部配置" && echo
    read -e -p "(默认: 取消):" mtp_modify
    [[ -z "${mtp_modify}" ]] && echo -e "${Error} 已取消..." && return 0
    case "${mtp_modify}" in
        1) Set_port;   Restart ;;
        2) Set_passwd; Restart ;;
        3) Set_tag;    Restart ;;
        4) Set_port; Set_passwd; Set_tag; Restart ;;
        *) echo -e "${Error} 请输入正确的数字(1-4)" ;;
    esac
}

Install(){
    [[ -e ${mtp_file} ]] && echo -e "${Error} 检测到 MTProxy 已安装 !" && exit 1
    install_base
    Download
    Set_port
    Set_passwd
    Set_tag
    echo -e "${Info} 所有步骤 执行完毕，开始启动..."
    Start
}

Start(){
    check_installed_status
    if check_service_status; then
        echo -e "${Error} MTProxy 正在运行，请检查 !"
        sleep 1s
        menu
    else
        start_mtproxy
        sleep 2s
        if check_service_status; then
            enable_mtproxy
            View
        else
            echo -e "${Error} MTProxy 启动失败，请检查日志！"
            echo -e "${Info} 使用 'journalctl -u mtpgo.service -n 50' 查看日志"
            sleep 3s
            menu
        fi
    fi
}

Stop(){
    check_installed_status
    if ! check_service_status; then
        echo -e "${Error} MTProxy 没有运行，请检查 !"
        sleep 1s
        menu
    else
        stop_mtproxy
        sleep 2s
        if ! check_service_status; then
            echo -e "${Info} MTProxy 已停止"
        else
            echo -e "${Error} MTProxy 停止失败"
        fi
        sleep 1s
        menu
    fi
}

Restart(){
    check_installed_status
    if check_service_status; then
        stop_mtproxy
        sleep 2s
    fi
    start_mtproxy
    sleep 2s
    if check_service_status; then
        View
    else
        echo -e "${Error} MTProxy 重启失败，请检查日志！"
        sleep 3s
        menu
    fi
}

# 更新 mtpgo 程序
Update(){
    check_installed_status
    echo -e "${Info} 开始更新 mtpgo 程序..."

    local latest_version
    latest_version=$(curl -Ls "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "$latest_version" ]]; then
        echo -e "${Error} 无法获取最新版本，请检查网络连接"
        return 1
    fi

    local current_version=""
    [[ -f "${mtp_dir}/version" ]] && current_version=$(cat "${mtp_dir}/version")

    if [[ "$current_version" == "$latest_version" ]]; then
        echo -e "${Info} mtpgo 已经是最新版本: ${latest_version}"
        sleep 2
        menu
        return 0
    fi

    echo -e "${Info} 发现新版本: ${latest_version}，当前版本: ${current_version:-未安装}"

    if check_service_status; then
        echo -e "${Info} 停止当前服务..."
        stop_mtproxy
        sleep 2
    fi

    [[ -f "$mtp_conf" ]] && cp "$mtp_conf" "${mtp_conf}.bak" && echo -e "${Info} 已备份配置文件"

    cd "${mtp_dir}" || exit 1
    check_arch
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${latest_version}/mtpgo-linux-${arch}.tar.gz"
    echo -e "${Info} 下载地址: $download_url"

    wget -q --show-progress -O "mtpgo-linux-${arch}.tar.gz" "$download_url"
    if [[ $? -ne 0 ]]; then
        echo -e "${Error} 下载失败，请检查网络连接"
        [[ -f "${mtp_conf}.bak" ]] && mv "${mtp_conf}.bak" "$mtp_conf"
        return 1
    fi

    tar xzf "mtpgo-linux-${arch}.tar.gz"
    rm -f "mtpgo-linux-${arch}.tar.gz"

    if [[ -f "${mtp_conf}.bak" ]] && [[ ! -f "$mtp_conf" ]]; then
        mv "${mtp_conf}.bak" "$mtp_conf"
    fi

    echo "$latest_version" > "${mtp_dir}/version"

    start_mtproxy
    sleep 2
    if check_service_status; then
        echo -e "${Info} mtpgo 更新完成！"
        enable_mtproxy
        View
    else
        echo -e "${Error} 服务启动失败，请检查日志"
        return 1
    fi
}

Uninstall(){
    check_installed_status
    echo -e "${Tip} 确定要卸载 MTProxy ? (y/N)"
    echo
    read -e -p "(默认: n):" unyn
    [[ -z ${unyn} ]] && unyn="n"
    if [[ ${unyn} == [Yy] ]]; then
        if check_service_status; then
            stop_mtproxy
        fi

        disable_mtproxy

        # 删除服务文件
        if [[ "$release" == "alpine" ]]; then
            rm -f /etc/init.d/mtpgo
        else
            rm -f /lib/systemd/system/mtpgo.service
            systemctl daemon-reload >/dev/null 2>&1
        fi

        rm -rf "${mtp_dir}"
        echo -e "${Info} MTProxy 卸载完成 !"
        echo
    else
        echo
        echo -e "${Tip} 卸载已取消..."
        echo
    fi
}

View(){
    check_installed_status
    Read_config
    clear && echo
    echo -e "Mtproto Proxy 用户配置："
    echo -e "————————————————"
    echo -e " 地址\t: ${Green}${IPv4}${Nc}"
    [[ -n "${IPv6}" ]] && echo -e " 地址\t: ${Green}${IPv6}${Nc}"
    echo -e " 端口\t: ${Green}${PORT}${Nc}"
    echo -e " 密匙\t: ${Green}${SECURE}${Nc}"
    [[ -n "${TAG}" ]] && echo -e " TAG \t: ${Green}${TAG}${Nc}"
    echo -e " IPv4 链接\t: ${Red}https://t.me/proxy?server=${IPv4}&port=${PORT}&secret=${SECURE}${Nc}"
    echo -e " IPv4 链接\t: ${Red}tg://proxy?server=${IPv4}&port=${PORT}&secret=${SECURE}${Nc}"
    [[ -n "${IPv6}" ]] && echo -e " IPv6 链接\t: ${Red}tg://proxy?server=${IPv6}&port=${PORT}&secret=${SECURE}${Nc}"
    [[ -n "${IPv6}" ]] && echo -e " IPv6 链接\t: ${Red}https://t.me/proxy?server=${IPv6}&port=${PORT}&secret=${SECURE}${Nc}"
    echo
    echo -e "${Tip} 密匙头部的 ${Green}ee${Nc} 字符是代表客户端启用 ${Green}TLS伪装模式${Nc} ，可以降低服务器被墙几率。"
    echo -e "${Tip} 密匙头部的 ${Green}dd${Nc} 字符是代表客户端启用 ${Green}安全混淆模式${Nc}（TLS伪装模式除外），可以降低服务器被墙几率。"
    backmenu
}

View_Log(){
    check_installed_status
    echo && echo -e "${Tip} 按 ${Red}Ctrl+C${Nc} 终止查看日志。"
    tail -f /var/mtpgo/log_mtpgo
}

Esc_Shell(){
    exit 0
}

backmenu(){
    echo ""
    read -rp "请输入\"y\"退出, 或按任意键回到主菜单：" backmenuInput
    case "$backmenuInput" in
        y) exit 0 ;;
        *) menu ;;
    esac
}

menu(){
    clear
    echo -e "${Green}######################################
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
———————————————————————" && echo

    if [[ -e ${mtp_file} ]]; then
        if check_service_status; then
            echo -e " 当前状态: ${Green}已安装${Nc} 并 ${Green}已启动${Nc}"
            if [[ -f "$mtp_info" ]]; then
                Read_config
                echo -e "${Info} IPv4 链接: ${Red}https://t.me/proxy?server=${IPv4}&port=${PORT}&secret=${SECURE}${Nc}"
                [[ -n "${IPv6}" ]] && echo -e "${Info} IPv6 链接: ${Red}https://t.me/proxy?server=${IPv6}&port=${PORT}&secret=${SECURE}${Nc}"
            fi
        else
            echo -e " 当前状态: ${Green}已安装${Nc} 但 ${Red}未启动${Nc}"
        fi
    else
        echo -e " 当前状态: ${Red}未安装${Nc}"
    fi
    echo
    read -e -p " 请输入数字 [0-9]:" num
    case "$num" in
        0) Esc_Shell ;;
        1) Install ;;
        2) Uninstall ;;
        3) Update ;;
        4) Start ;;
        5) Stop ;;
        6) Restart ;;
        7) Set ;;
        8) View ;;
        9) View_Log ;;
        *) echo -e "${Error} 请输入正确数字 [0-9]" ;;
    esac
}

check_root
menu
