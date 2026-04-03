package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mtproxy/config"
	"mtproxy/crypto"
	"mtproxy/proxy"
	"mtproxy/stats"
)

// ── 日志 ──────────────────────────────────────────────────────────────────────

var logWriter io.Writer = os.Stderr

func setupLogger() {
	logDir := filepath.Dir(os.Args[0])
	logPath := filepath.Join(logDir, "log_mtpgo")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法创建日志文件 %s: %v\n", logPath, err)
		return
	}
	logWriter = io.MultiWriter(os.Stderr, logFile)
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(logWriter, format, args...)
}

// ── 获取公网 IP ───────────────────────────────────────────────────────────────

func getNetIface() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "eth") ||
			strings.HasPrefix(name, "ens") ||
			strings.HasPrefix(name, "enp") {
			return name
		}
	}
	return ""
}

func newHTTPClient(network, iface string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if iface != "" {
		dialer.Control = func(net_, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BINDTODEVICE, iface)
			})
		}
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

func getIPFromURL(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	result := strings.TrimSpace(string(body))
	if net.ParseIP(result) == nil {
		return ""
	}
	return result
}

func getFirstIP(client *http.Client, urls []string) string {
	for _, url := range urls {
		if ip := getIPFromURL(client, url); ip != "" {
			return ip
		}
	}
	return ""
}

func initIPInfo(cfg *config.Config) {
	iface := getNetIface()

	ipURLs := []string{
		"http://ip.gs",
		"http://ip.sb",
		"http://ident.me",
		"http://ifconfig.me",
		"http://api.ipify.org",
		"http://icanhazip.com",
	}

	clientV4 := newHTTPClient("tcp4", iface)
	clientV6 := newHTTPClient("tcp6", iface)

	ipv4 := getFirstIP(clientV4, ipURLs)
	ipv6 := getFirstIP(clientV6, ipURLs)

	if ipv6 != "" && !strings.Contains(ipv6, ":") {
		ipv6 = ""
	}

	proxy.MyIPInfo.Set(ipv4, ipv6)

	if ipv6 != "" && (cfg.PreferIPv6 || ipv4 == "") {
		logf("IPv6 found, using it for external communication\n")
	}
	if ipv4 == "" && ipv6 == "" {
		logf("Failed to determine your ip\n")
	}
}

// ── 打印代理链接 ──────────────────────────────────────────────────────────────

func printTGInfo(cfg *config.Config) []map[string]string {
	ipv4, ipv6 := proxy.MyIPInfo.Get()
	var ipAddrs []string

	if cfg.MyDomain != "" {
		ipAddrs = []string{cfg.MyDomain}
	} else {
		if ipv4 != "" {
			ipAddrs = append(ipAddrs, ipv4)
		}
		if ipv6 != "" {
			ipAddrs = append(ipAddrs, ipv6)
		}
		if len(ipAddrs) == 0 {
			logf("Warning: could not determine public IP\n")
			return nil
		}
	}

	defaultSecrets := map[string]bool{
		"00000000000000000000000000000000": true,
		"0123456789abcdef0123456789abcdef": true,
		"00000000000000000000000000000001": true,
	}

	var links []map[string]string
	printDefault := false

	for _, secret := range cfg.Secrets {
		secretHex := hex.EncodeToString(secret)
		for _, ip := range ipAddrs {
			if cfg.Modes.Classic {
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s",
					ip, cfg.Port, secretHex)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				logf("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
			if cfg.Modes.Secure {
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=dd%s",
					ip, cfg.Port, secretHex)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				logf("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
			if cfg.Modes.TLS {
				tlsSecret := "ee" + secretHex + hex.EncodeToString([]byte(cfg.TLSDomain))
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s",
					ip, cfg.Port, tlsSecret)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				logf("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
		}

		if defaultSecrets[secretHex] {
			logf("The default secret %s is used, this is not recommended\n", secretHex)
			rnd := crypto.GlobalRand.Bytes(16)
			logf("You can change it to this random secret: %s\n", hex.EncodeToString(rnd))
			printDefault = true
		}
	}

	if cfg.TLSDomain == "www.google.com" {
		logf("The default TLS_DOMAIN www.google.com is used, this is not recommended\n")
		printDefault = true
	}
	if printDefault {
		logf("Warning: one or more default settings detected\n")
	}

	return links
}

// ── 服务器启动 ────────────────────────────────────────────────────────────────

// startServers 启动所有监听器并返回它们的 Closer 列表。
// 接受 *config.AtomicConfig 而非裸 *config.Config，确保 acceptLoop 中的每个连接
// 都能通过 atomicCfg.Get() 拿到最新配置快照，热重载后新连接立即使用新配置。
func startServers(atomicCfg *config.AtomicConfig) []io.Closer {
	cfg := atomicCfg.Get()
	var listeners []io.Closer

	if cfg.ListenAddrIPv4 != "" {
		addr := fmt.Sprintf("%s:%d", cfg.ListenAddrIPv4, cfg.Port)
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			logf("Failed to listen on %s: %v\n", addr, err)
		} else {
			logf("Listening on %s\n", addr)
			listeners = append(listeners, ln)
			go acceptLoop(ln, atomicCfg)
		}
	}

	if cfg.ListenAddrIPv6 != "" {
		addr := fmt.Sprintf("[%s]:%d", cfg.ListenAddrIPv6, cfg.Port)
		ln, err := net.Listen("tcp6", addr)
		if err != nil {
			logf("Failed to listen on %s: %v\n", addr, err)
		} else {
			logf("Listening on %s\n", addr)
			listeners = append(listeners, ln)
			go acceptLoop(ln, atomicCfg)
		}
	}

	if cfg.ListenUnixSock != "" {
		os.Remove(cfg.ListenUnixSock)
		ln, err := net.Listen("unix", cfg.ListenUnixSock)
		if err != nil {
			logf("Failed to listen on unix %s: %v\n", cfg.ListenUnixSock, err)
		} else {
			listeners = append(listeners, ln)
			go acceptLoop(ln, atomicCfg)
		}
	}

	return listeners
}

// acceptLoop 持续接受新连接，每次连接时通过 atomicCfg.Get() 取得当前配置快照。
// 这样热重载后新建立的连接会使用新配置，已有连接不受影响（符合预期语义）。
func acceptLoop(ln net.Listener, atomicCfg *config.AtomicConfig) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// 每次 Accept 后取一次配置快照，传给 HandleClientWrapper。
		// HandleClientWrapper 内部是单次连接的完整生命周期，使用快照即可，
		// 无需在连接过程中感知配置变更。
		go proxy.HandleClientWrapper(conn, atomicCfg.Get())
	}
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	setupLogger()
	proxy.SetLogger(logWriter)

	configPath := config.ParseArgs()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logf("配置加载失败: %v\n", err)
		os.Exit(1)
	}

	// 用 AtomicConfig 统一管理配置，所有 goroutine 通过它读写，保证热重载的并发安全。
	atomicCfg := config.NewAtomicConfig(cfg)

	proxy.UsedHandshakes = proxy.NewReplayCache(cfg.ReplayCheckLen)
	proxy.ClientIPs = proxy.NewReplayCache(cfg.ClientIPsLen)

	initIPInfo(cfg)
	proxy.SetMaskHost(cfg.MaskHost)
	currentProxyLinks := printTGInfo(cfg)

	// 后台 goroutine 传入 atomicCfg，内部通过 Get() 读取最新配置。
	// StatsPrinter / GetMaskHostCertLen / UpdateMiddleProxyInfo 都是长期循环，
	// 热重载后它们在下一次循环迭代时会自动拿到新配置。
	go stats.StatsPrinterAtomic(atomicCfg, logf)
	go proxy.GetMaskHostCertLenAtomic(atomicCfg)
	go proxy.ClearIPResolvingCache()

	if cfg.UseMiddleProxy {
		go proxy.UpdateMiddleProxyInfoAtomic(atomicCfg)
	}

	stats.StartMetricsServerAtomic(atomicCfg, currentProxyLinks)

	listeners := startServers(atomicCfg)
	if len(listeners) == 0 {
		logf("没有可用的监听地址，退出\n")
		os.Exit(1)
	}

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGUSR2)
	go func() {
		for range reloadCh {
			newCfg, err := config.LoadConfig(configPath)
			if err != nil {
				logf("配置重载失败: %v\n", err)
				continue
			}
			// Set 内部用写锁原子替换指针，不存在半更新状态。
			atomicCfg.Set(newCfg)
			// 重置 ReplayCache（新配置可能改变了 ReplayCheckLen）
			proxy.UsedHandshakes = proxy.NewReplayCache(newCfg.ReplayCheckLen)
			proxy.SetMaskHost(newCfg.MaskHost)
			currentProxyLinks = printTGInfo(newCfg)
			logf("Config reloaded\n")
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logf("Shutting down...\n")
	for _, ln := range listeners {
		ln.Close()
	}
}
