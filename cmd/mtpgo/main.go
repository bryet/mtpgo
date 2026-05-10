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
	"sync"
	"syscall"
	"time"

	"mtproxy/config"
	"mtproxy/crypto"
	"mtproxy/proxy"
	"mtproxy/stats"
)

// ── 日志 ──────────────────────────────────────────────────────────────────────

var logWriter io.Writer = os.Stderr
var logFile *os.File

func setupLogger() {
	logDir := filepath.Dir(os.Args[0])
	logPath := filepath.Join(logDir, "log_mtpgo")
	var err error
	logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法创建日志文件 %s: %v\n", logPath, err)
		return
	}
	logWriter = io.MultiWriter(os.Stderr, logFile)
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(logWriter, format, args...)
}

func infof(format string, args ...interface{})  { fmt.Fprintf(logWriter, "[INFO]  "+format, args...) }
func warnf(format string, args ...interface{})  { fmt.Fprintf(logWriter, "[WARN]  "+format, args...) }
func errorf(format string, args ...interface{}) { fmt.Fprintf(logWriter, "[ERROR] "+format, args...) }

// ── 获取公网 IP（遍历所有网口）─────────────────────────────────────────────────

// getNetIfaces 返回所有物理网卡名（eth/ens/enp 开头）
func getNetIfaces() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var ifaces []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "eth") ||
			strings.HasPrefix(name, "ens") ||
			strings.HasPrefix(name, "enp") {
			ifaces = append(ifaces, name)
		}
	}
	return ifaces
}

// newHTTPClient 创建绑定指定网卡的 HTTP 客户端
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

// getFirstIPConcurrent 并发请求所有 URL，返回最快成功的结果
func getFirstIPConcurrent(client *http.Client, urls []string) string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct{ ip string }
	ch := make(chan result, len(urls))

	for _, url := range urls {
		url := url
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				ch <- result{""}
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				ch <- result{""}
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				ch <- result{""}
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				ch <- result{""}
				return
			}
			ip := strings.TrimSpace(string(body))
			if net.ParseIP(ip) == nil {
				ip = ""
			}
			ch <- result{ip}
		}()
	}

	for range urls {
		if r := <-ch; r.ip != "" {
			cancel()
			return r.ip
		}
	}
	return ""
}

// getIPWithFallback 遍历所有网口获取 IP
func getIPWithFallback(urls []string, ifaces []string, isIPv6 bool) string {
	for _, iface := range ifaces {
		network := "tcp4"
		if isIPv6 {
			network = "tcp6"
		}
		client := newHTTPClient(network, iface)
		if ip := getFirstIPConcurrent(client, urls); ip != "" {
			return ip
		}
	}
	// 最后尝试不绑定网卡
	network := "tcp4"
	if isIPv6 {
		network = "tcp6"
	}
	client := newHTTPClient(network, "")
	return getFirstIPConcurrent(client, urls)
}

func initIPInfo(cfg *config.Config) {
	ifaces := getNetIfaces()
	if len(ifaces) == 0 {
		warnf("No network interfaces found (eth/ens/enp), trying without binding\n")
		ifaces = []string{""}
	}

	ipURLs := []string{
		"http://ip.gs",
		"http://ip.sb",
		"http://ident.me",
		"http://ifconfig.me",
		"http://api.ipify.org",
		"http://icanhazip.com",
	}

	// 获取 IPv4：遍历所有网口
	ipv4 := getIPWithFallback(ipURLs, ifaces, false)

	// 获取 IPv6：遍历所有网口
	ipv6 := getIPWithFallback(ipURLs, ifaces, true)

	if ipv6 != "" && !strings.Contains(ipv6, ":") {
		ipv6 = ""
	}
	proxy.MyIPInfo.Set(ipv4, ipv6)

	if ipv6 != "" && (cfg.PreferIPv6 || ipv4 == "") {
		infof("IPv6 found, using it for external communication\n")
	}
	if ipv4 == "" && ipv6 == "" {
		warnf("Failed to determine your ip\n")
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
			warnf("Warning: could not determine public IP\n")
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
				infof("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
			if cfg.Modes.Secure {
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=dd%s",
					ip, cfg.Port, secretHex)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				infof("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
			if cfg.Modes.TLS {
				tlsSecret := "ee" + secretHex + hex.EncodeToString([]byte(cfg.TLSDomain))
				link := fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s",
					ip, cfg.Port, tlsSecret)
				links = append(links, map[string]string{"secret": secretHex, "link": link})
				infof("\033[31mMtproxyurl: %s\033[0m\n", link)
			}
		}
		if defaultSecrets[secretHex] {
			warnf("The default secret %s is used, this is not recommended\n", secretHex)
			rnd := crypto.GlobalRand.Bytes(16)
			infof("You can change it to this random secret: %s\n", hex.EncodeToString(rnd))
			printDefault = true
		}
	}

	if cfg.TLSDomain == "www.google.com" {
		warnf("The default TLS_DOMAIN www.google.com is used, this is not recommended\n")
		printDefault = true
	}
	if printDefault {
		warnf("Warning: one or more default settings detected\n")
	}
	return links
}

// ── 服务器启动 ────────────────────────────────────────────────────────────────

const shutdownTimeout = 5 * time.Second

func acceptLoop(ln net.Listener, acfg *config.AtomicConfig, wg *sync.WaitGroup) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.HandleClientWrapper(conn, acfg.Get())
		}()
	}
}

func startServers(acfg *config.AtomicConfig, wg *sync.WaitGroup) []io.Closer {
	cfg := acfg.Get()
	var listeners []io.Closer

	if cfg.ListenAddrIPv4 != "" {
		addr := fmt.Sprintf("%s:%d", cfg.ListenAddrIPv4, cfg.Port)
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			errorf("Failed to listen on %s: %v\n", addr, err)
		} else {
			listeners = append(listeners, ln)
			go acceptLoop(ln, acfg, wg)
		}
	}

	if cfg.ListenAddrIPv6 != "" {
		addr := fmt.Sprintf("[%s]:%d", cfg.ListenAddrIPv6, cfg.Port)
		ln, err := net.Listen("tcp6", addr)
		if err != nil {
			errorf("Failed to listen on %s: %v\n", addr, err)
		} else {
			listeners = append(listeners, ln)
			go acceptLoop(ln, acfg, wg)
		}
	}

	if cfg.ListenUnixSock != "" {
		os.Remove(cfg.ListenUnixSock)
		ln, err := net.Listen("unix", cfg.ListenUnixSock)
		if err != nil {
			errorf("Failed to listen on unix %s: %v\n", cfg.ListenUnixSock, err)
		} else {
			listeners = append(listeners, ln)
			go acceptLoop(ln, acfg, wg)
		}
	}

	return listeners
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	setupLogger()
	proxy.SetLogger(logWriter)

	configPath := config.ParseArgs()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		errorf("配置加载失败: %v\n", err)
		os.Exit(1)
	}

	acfg := config.NewAtomicConfig(cfg)

	proxy.SetLogLevel(cfg.LogLevel)
	proxy.UsedHandshakes = proxy.NewReplayCache(cfg.ReplayCheckLen)
	proxy.ClientIPs = proxy.NewReplayCache(cfg.ClientIPsLen)

	initIPInfo(cfg)
	proxy.SetMaskHost(cfg.MaskHost)
	currentProxyLinks := printTGInfo(cfg)

	go stats.StatsPrinter(cfg, logf)
	go proxy.GetMaskHostCertLen(cfg)
	go proxy.ClearIPResolvingCache()

	if cfg.UseMiddleProxy {
		go proxy.UpdateMiddleProxyInfo(cfg)
	}

	stats.StartMetricsServer(cfg, currentProxyLinks)

	var wg sync.WaitGroup

	listeners := startServers(acfg, &wg)
	if len(listeners) == 0 {
		errorf("没有可用的监听地址，退出\n")
		os.Exit(1)
	}

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGUSR2)
	go func() {
		for range reloadCh {
			newCfg, err := config.LoadConfig(configPath)
			if err != nil {
				errorf("配置重载失败: %v\n", err)
				continue
			}
			acfg.Set(newCfg)
			proxy.SetLogLevel(newCfg.LogLevel)
			proxy.UsedHandshakes = proxy.NewReplayCache(newCfg.ReplayCheckLen)
			proxy.SetMaskHost(newCfg.MaskHost)
			currentProxyLinks = printTGInfo(newCfg)
			infof("Config reloaded\n")
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	infof("Shutting down...\n")

	for _, ln := range listeners {
		ln.Close()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		infof("All connections closed.\n")
	case <-time.After(shutdownTimeout):
		warnf("Shutdown timeout (%s), forcing exit.\n", shutdownTimeout)
	}

	if logFile != nil {
		logFile.Close()
	}
}
