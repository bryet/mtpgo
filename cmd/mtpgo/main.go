package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mtproxy/config"
	"mtproxy/proxy"
	"mtproxy/stats"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ── 日志 ──────────────────────────────────────────────────────────────────────

var logWriter io.Writer = os.Stderr
var logFile *os.File

func setupLogger() {
	exe, _ := os.Executable()
	logDir := os.Getenv("MTPGO_LOG_DIR")
	if logDir == "" {
		logDir = filepath.Dir(exe)
	}
	logPath := filepath.Join(logDir, "log_mtpgo")
	var err error
	logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法创建日志文件 %s: %v\n", logPath, err)
		return
	}
	logWriter = io.MultiWriter(os.Stderr, logFile)
}

func logf(format string, args ...interface{}) {
	proxy.Logf(format, args...)
}

func infof(format string, args ...interface{})  { proxy.Infof(format, args...) }
func warnf(format string, args ...interface{})  { proxy.Warnf(format, args...) }
func errorf(format string, args ...interface{}) { proxy.Errorf(format, args...) }

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
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			})
			if err != nil {
				return err
			}
			return sockErr
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
			body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
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
		defer client.CloseIdleConnections()
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
	defer client.CloseIdleConnections()
	return getFirstIPConcurrent(client, urls)
}

func initIPInfo(cfg *config.Config) {
	ifaces := getNetIfaces()
	if len(ifaces) == 0 {
		warnf("No network interfaces found (eth/ens/enp), trying without binding\n")
		ifaces = []string{""}
	}

	ipURLs := []string{
		"https://ip.gs",
		"https://ip.sb",
		"https://ident.me",
		"https://ifconfig.me",
		"https://api.ipify.org",
		"https://icanhazip.com",
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

func buildProxyLinks(cfg *config.Config) []map[string]string {
	ipv4, ipv6 := proxy.MyIPInfo.Get()
	hosts := []string{}
	if cfg.MyDomain != "" {
		hosts = append(hosts, cfg.MyDomain)
	} else {
		if ipv4 != "" {
			hosts = append(hosts, ipv4)
		}
		if ipv6 != "" {
			hosts = append(hosts, ipv6)
		}
	}
	var links []map[string]string
	for _, secret := range cfg.Secrets {
		base := hex.EncodeToString(secret)
		var secrets []string
		if cfg.Modes.Classic {
			secrets = append(secrets, base)
		}
		if cfg.Modes.Secure {
			secrets = append(secrets, "dd"+base)
		}
		if cfg.Modes.TLS {
			secrets = append(secrets, "ee"+base+hex.EncodeToString([]byte(cfg.TLSDomain)))
		}
		for _, host := range hosts {
			for _, sec := range secrets {
				values := url.Values{"server": {host}, "port": {fmt.Sprint(cfg.Port)}, "secret": {sec}}
				links = append(links, map[string]string{"secret": base, "link": "https://t.me/proxy?" + values.Encode()})
			}
		}
	}
	return links
}
func printTGInfo(cfg *config.Config) {
	links := buildProxyLinks(cfg)
	if len(links) == 0 {
		warnf("Could not determine public IP; set MY_DOMAIN to advertise a hostname\n")
	}
	// Links contain credentials: print to the interactive terminal only, not the
	// persistent log or journal. Metrics export is a separate explicit opt-in.
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		for _, link := range links {
			fmt.Fprintf(os.Stdout, "Mtproxyurl: %s\n", link["link"])
		}
	}
}

// ── 服务器启动 ────────────────────────────────────────────────────────────────

const shutdownTimeout = 5 * time.Second

type connectionGroup struct {
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
	wg      sync.WaitGroup
}

func (g *connectionGroup) add(c net.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return false
	}
	g.conns[c] = struct{}{}
	g.wg.Add(1)
	return true
}
func (g *connectionGroup) done(c net.Conn) {
	g.mu.Lock()
	delete(g.conns, c)
	g.mu.Unlock()
	g.wg.Done()
}
func (g *connectionGroup) closeAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closing = true
	for c := range g.conns {
		c.Close()
	}
}
func acceptLoop(ln net.Listener, a *config.AtomicConfig, g *connectionGroup, acceptWG *sync.WaitGroup) {
	defer acceptWG.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				errorf("Accept failed: %v\n", err)
			}
			return
		}
		if !g.add(conn) {
			conn.Close()
			continue
		}
		cfg := a.Get()
		go func() { defer g.done(conn); proxy.HandleClientWrapper(conn, cfg) }()
	}
}
func startServers(a *config.AtomicConfig, g *connectionGroup, acceptWG *sync.WaitGroup) []net.Listener {
	cfg := a.Get()
	var listeners []net.Listener
	for _, item := range []struct{ network, addr string }{{"tcp4", net.JoinHostPort(cfg.ListenAddrIPv4, fmt.Sprint(cfg.Port))}, {"tcp6", net.JoinHostPort(cfg.ListenAddrIPv6, fmt.Sprint(cfg.Port))}, {"unix", cfg.ListenUnixSock}} {
		if item.network == "tcp4" && cfg.ListenAddrIPv4 == "" || item.network == "tcp6" && cfg.ListenAddrIPv6 == "" || item.network == "unix" && item.addr == "" {
			continue
		}
		// Never unlink an arbitrary file or an active Unix listener.
		ln, err := net.Listen(item.network, item.addr)
		if err != nil {
			errorf("Listen %s %s: %v\n", item.network, item.addr, err)
			continue
		}
		listeners = append(listeners, ln)
		acceptWG.Add(1)
		go acceptLoop(ln, a, g, acceptWG)
	}
	return listeners
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	configPath := config.ParseArgs()
	setupLogger()
	proxy.SetLogger(logWriter)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		errorf("配置加载失败: %v\n", err)
		os.Exit(1)
	}
	a := config.NewAtomicConfig(cfg)
	proxy.SetLogLevel(cfg.LogLevel)
	proxy.UsedHandshakes.Resize(cfg.ReplayCheckLen)
	initIPInfo(cfg)
	printTGInfo(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var background sync.WaitGroup
	for _, task := range []func(context.Context, *config.AtomicConfig){
		func(ctx context.Context, a *config.AtomicConfig) { stats.StatsPrinter(ctx, a, logf) }, proxy.GetMaskHostCertLen, proxy.UpdateMiddleProxyInfo,
	} {
		background.Add(1)
		go func() { defer background.Done(); task(ctx, a) }()
	}
	metrics, err := stats.StartMetricsServer(a, buildProxyLinks, errorf)
	if err != nil {
		errorf("%v\n", err)
		os.Exit(1)
	}
	g := &connectionGroup{conns: make(map[net.Conn]struct{})}
	var acceptWG sync.WaitGroup
	listeners := startServers(a, g, &acceptWG)
	if len(listeners) == 0 {
		errorf("没有可用监听地址\n")
		os.Exit(1)
	}
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGUSR2, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	for sig := range sigCh {
		if sig != syscall.SIGUSR2 {
			break
		}
		next, err := config.LoadConfig(configPath)
		if err == nil {
			err = config.ValidateReload(a.Get(), next)
		}
		if err != nil {
			errorf("配置重载失败: %v\n", err)
			continue
		}
		proxy.UsedHandshakes.Resize(next.ReplayCheckLen)
		a.Set(next)
		proxy.SetLogLevel(next.LogLevel)
		printTGInfo(next)
		infof("Config reloaded\n")
	}
	infof("Shutting down...\n")
	cancel()
	for _, ln := range listeners {
		ln.Close()
	}
	acceptWG.Wait() // No WaitGroup.Add can race with waiting for clients.
	shutdownCtx, stop := context.WithTimeout(context.Background(), shutdownTimeout)
	defer stop()
	stats.ShutdownMetrics(shutdownCtx, metrics)
	done := make(chan struct{})
	go func() { g.wg.Wait(); background.Wait(); close(done) }()
	select {
	case <-done:
		infof("All connections closed.\n")
	case <-shutdownCtx.Done():
		g.closeAll()
		warnf("Shutdown timeout; active connections closed\n")
	}
	proxy.SetLogger(io.Discard)
	if logFile != nil {
		logFile.Close()
	}
}
