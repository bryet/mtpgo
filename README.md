# mtpgo — Go 版 Telegram MTProto 代理

支持 Linux `386 / amd64 / arm64 / armv7 / armv6 / armv5 / s390x`、IPv4/IPv6、多 secret，以及通过 Telegram 中间代理携带频道推广 TAG。

## 协议模式

- **Classic**：普通 MTProto 混淆，链接使用 32 位 hex secret。
- **Secure**：带随机填充的混淆，链接 secret 前缀为 `dd`。
- **FakeTLS**：链接前缀为 `ee`，附加 TLS 域名的 hex 编码。ClientHello 使用 HMAC 验证，后续 MTProto 混淆数据封装为 TLS 记录外观。

**FakeTLS 不是标准 TLS 会话，不能替代真实 TLS 的安全保证。** 简洁配置模板默认选择 Secure，安装脚本交互默认选择 FakeTLS；配置缺失模式开关时，为兼容旧配置，三种模式均启用。

标准 JA3（MD5）/JA4 用于 debug 诊断；历史非标准指纹黑名单仍单独执行，并明确标注为 legacy。诊断指纹不是客户端身份验证，secret 验证仍是必需的。

## 构建与手动启动

需要 Go 1.26 或更新版本：

```bash
go build -trimpath -o mtpgo ./cmd/mtpgo
./mtpgo -s                  # 生成随机 32 位 hex 密钥
```

先将 `config.example.ini` 复制为运行配置 `config.ini`，再将生成的密钥填入 `SECRET`：

```bash
cp config.example.ini config.ini
./mtpgo -check -c config.ini # 只验证配置，不创建日志或连接网络
./mtpgo -c config.ini
./mtpgo -v
```

空 secret、格式错误、重复 secret，以及公开的全零/示例 secret 均拒绝启动。`SECRET` 支持逗号分隔多个密钥。端口、超时、布尔值、TAG、白名单和监听地址均严格校验；未知配置项报错，不再静默忽略。

`TLS_DOMAIN` 填写可访问的域名；`MASK_HOST` 默认与其相同。`MY_DOMAIN` 可指定对外公布的主机名，避免依赖公网 IP 探测。`AD_TAG` 从 https://t.me/MTProxybot 获取，必须是 32 位 hex；留空则直连 Telegram DC。

## 安装管理脚本

## ✨golang版TG代理

>适配 /386/amd64/arm64/armv7/armv6/s390x 架构
>
>支持ipv4和ipv6
>
>默认开启混淆伪装和TLS加密
>
>支持TG频道推广（需要TG2021年及之前的老号）

## ✨一键脚本
```
bash <(curl -sSL https://raw.githubusercontent.com/bryet/mtpgo/main/mtproxy.sh)
```

🟢 DOMAIN 找一个没有被墙的网站的域名

🟢 TAG 从机器人 https://t.me/MTProxybot 获取

脚本按 `mtproxy.example.sh` 保留彩色 0–9 菜单、端口/密钥/TAG 设置及链接展示。脚本需要 root 来安装服务，但代理进程使用专用 `mtpgo` 用户：

- 程序及配置：`/var/mtpgo/`，目录由 root 管理；配置权限 `root:mtpgo 0640`。
- 日志：`/var/log/mtpgo/log_mtpgo`。
- 运行目录：`/run/mtpgo/`，Unix Socket 建议放在该目录。
- systemd 允许绑定低端口；OpenRC 默认无低端口能力，请使用 1024 以上端口。

下载使用证书验证的 HTTPS，并校验 Release 的 `SHA256SUMS.txt`。校验用于检测下载损坏/不一致，不替代独立签名或对发布账户的信任。安装与升级统一在 `/tmp/mtpgo.XXXXXXXX/` 私有目录下载，验证路径及文件类型后解压至其中的独立子目录，不会直接覆盖安装目录，也不受 `TMPDIR` 或当前工作目录影响。

升级先下载并用新程序验证现有配置，全部通过后才停止旧服务。升级不替换用户 `config.ini` 或 `mtp_info`，原子替换程序，成功后才更新版本文件；失败或可处理的中断会回滚旧程序、服务文件及版本。成功或回滚完成后清理临时目录；若回滚失败，保留备份并报告路径。原本停止的服务不会被升级操作自动启动。配置编辑同样先修改候选文件，校验成功后再替换。

查看链接以 `config.ini` 为准，旧 `mtp_info` 中的 PORT/SECURE 不再使用。直接编辑配置后需执行重载或重启，确保显示配置与实际运行一致。

## 配置与热重载

仓库和发布包中的模板名为 `config.example.ini`，初次安装时复制为运行配置 `config.ini`，升级不覆盖已有运行配置。模板只保留日志级别、端口、密钥、模式，以及可选的 TLS 域名和 TAG，内容为 INI 格式。未列出的高级参数继续使用程序默认值，需要时可自行追加；无需填写整套参数。以下时间单位均为秒：

| 参数 | 含义 |
|---|---|
| `TG_CONNECT_TIMEOUT` | 上游 TCP 建连和握手超时 |
| `TG_READ_TIMEOUT` | 转发时单次读取/上游写入的空闲超时，不是连接总寿命 |
| `CLIENT_HANDSHAKE_TIMEOUT` | 客户端握手超时；异常客户端伪装转发的最大持续时间 |
| `CLIENT_KEEPALIVE` | TCP keepalive 周期 |
| `CLIENT_ACK_TIMEOUT` | 单次客户端写入超时，不是 MTProto quickack 定时器 |
| `STATS_PRINT_PERIOD` | 统计日志间隔 |
| `PROXY_INFO_UPDATE_PERIOD` | 中间代理列表及 secret 更新间隔 |
| `GET_CERT_LEN_PERIOD` | 伪装主机证书长度探测间隔 |
| `REPLAY_CHECK_LEN` | 重放缓存容量；0 禁用。重载调整容量保留最近记录 |

`CLIENT_IPS_LEN` 从未实现，现已移除；旧配置若包含它，应删除。

```bash
systemctl reload mtpgo
# 或向进程发送 SIGUSR2
```

- 模式、secret、TAG 和连接参数用于**新连接**，已有连接保留握手时的配置。
- 日志级别和 metrics 白名单立即使用新配置。
- 后台统计、证书探测和上游更新在下一次调度检查（约 1 秒；正在进行的网络请求需先结束）使用新配置，包括从直连切换为中间代理。
- **代理及 metrics 监听端口/地址、Unix Socket 路径变更必须重启。** 如果本次重载包含这些变更，整次重载会被拒绝，旧配置保持不变。

`PROXY_PROTOCOL` 仅可用于可信反向代理后方，必须用防火墙限制来源；PROXY v1/v2 头本身不认证客户端身份。Unix Socket 配合中间代理时需用 PROXY 头提供 TCP 客户端地址。

## 日志与监控

- 日志受 `LOG_LEVEL` 控制，异常 panic 会记录堆栈，不再静默吞掉。
- `handshake_timeouts` 只计真正的网络超时；`connects_bad` 计所有被拒绝的握手。
- 流量在写入成功后计数。直连模式的消息计数是转发读取块数，不是解析后的 MTProto 消息数量。
- 用户标签使用 secret 的 SHA-256 派生标识，不暴露 secret 前缀。
- 链接包含密钥，仅输出到交互终端，不写入程序持久日志。脚本可重新显示所有链接。
- `METRICS_PORT=0` 默认关闭；启用后默认只监听本机并允许 loopback IP。白名单支持 IP/CIDR。
- `METRICS_EXPORT_LINKS=true` 会导出完整代理链接和 secret，只应对可信监控开启。
- 连接时长指标保留原有非累积 `bucket` 标签格式，不是标准 Prometheus histogram；不要直接使用 `histogram_quantile`。
- 日志文件目前不内建轮转；长期部署应配置 logrotate（例如 `copytruncate`），或通过服务管理器收集日志。

## 测试与发布

```bash
go test ./...
go vet ./...
CGO_ENABLED=1 go test -race ./...   # 需要 C 编译器
bash -n mtproxy.sh
bash tests/installer_test.sh       # 网络/账户/服务管理均 stub，不操作真实服务
bash tests/cli_test.sh             # 离线验证版本、密钥生成和配置校验
shellcheck -x mtproxy.sh mtpgo_openrc tests/*.sh
go test ./proxy -run '^$' -fuzz FuzzClientHello -fuzztime 10s
go test ./proto -run '^$' -fuzz FuzzProxyProtocol -fuzztime 10s
go test ./proto -run '^$' -fuzz FuzzFrameLength -fuzztime 10s
```

发布前 CI 运行回归测试、race、静态检查和解析器 fuzz。手动触发 Release 流程时，版本号通过显式环境变量传入构建，写入二进制及 Release 标签。

许可证：GPL-3.0，见 `LICENSE`。
