package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/ini.v1"
	"mtproxy/version"
)

const (
	SkipLen      = 8
	PrekeyLen    = 32
	KeyLen       = 32
	IVLen        = 16
	HandshakeLen = 64
	ProtoTagPos  = 56
	DCIdxPos     = 60
)

type Modes struct{ Classic, Secure, TLS bool }

type Config struct {
	Port      int
	Secrets   [][]byte
	ADTag     []byte
	Modes     Modes
	TLSDomain string

	UseMiddleProxy bool
	PreferIPv6     bool
	FastMode       bool
	ProxyProtocol  bool
	Mask           bool
	MaskHost       string
	MaskPort       int
	MyDomain       string

	ListenAddrIPv4      string
	ListenAddrIPv6      string
	ListenUnixSock      string
	MetricsPort         int
	MetricsListenAddrV4 string
	MetricsListenAddrV6 string
	MetricsPrefix       string
	MetricsWhitelist    []string
	MetricsExportLinks  bool

	ReplayCheckLen         int
	StatsPrintPeriod       int
	ProxyInfoUpdatePeriod  int
	GetCertLenPeriod       int
	TGConnectTimeout       int
	TGReadTimeout          int
	ClientHandshakeTimeout int
	ClientKeepalive        int
	ClientAckTimeout       int
	IgnoreTimeSkew         bool
	LogLevel               string
}

// Config snapshots are immutable after publication, including their slices.
type AtomicConfig struct {
	mu  sync.RWMutex
	cfg *Config
}

func NewAtomicConfig(cfg *Config) *AtomicConfig { return &AtomicConfig{cfg: cfg} }
func (a *AtomicConfig) Get() *Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}
func (a *AtomicConfig) Set(cfg *Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg
}

var secretHexRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var metricPrefixRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

func DefaultConfig() *Config {
	return &Config{
		Port: 3256, TLSDomain: "www.google.com", Modes: Modes{true, true, true},
		Mask: true, MaskPort: 443, ListenAddrIPv4: "0.0.0.0", ListenAddrIPv6: "::",
		MetricsListenAddrV4: "127.0.0.1", MetricsListenAddrV6: "::1", MetricsPrefix: "mtproxy_",
		MetricsWhitelist: []string{"127.0.0.1", "::1"}, ReplayCheckLen: 65536,
		StatsPrintPeriod: 60, ProxyInfoUpdatePeriod: 3600, GetCertLenPeriod: 14400,
		TGConnectTimeout: 10, TGReadTimeout: 60, ClientHandshakeTimeout: 10,
		ClientKeepalive: 10, ClientAckTimeout: 10, FastMode: true, LogLevel: "info",
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	f, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	sec := f.Section("")
	ints := map[string]*int{
		"PORT": &cfg.Port, "MASK_PORT": &cfg.MaskPort, "METRICS_PORT": &cfg.MetricsPort,
		"REPLAY_CHECK_LEN": &cfg.ReplayCheckLen, "STATS_PRINT_PERIOD": &cfg.StatsPrintPeriod,
		"PROXY_INFO_UPDATE_PERIOD": &cfg.ProxyInfoUpdatePeriod, "GET_CERT_LEN_PERIOD": &cfg.GetCertLenPeriod,
		"TG_CONNECT_TIMEOUT": &cfg.TGConnectTimeout, "TG_READ_TIMEOUT": &cfg.TGReadTimeout,
		"CLIENT_HANDSHAKE_TIMEOUT": &cfg.ClientHandshakeTimeout, "CLIENT_KEEPALIVE": &cfg.ClientKeepalive,
		"CLIENT_ACK_TIMEOUT": &cfg.ClientAckTimeout,
	}
	bools := map[string]*bool{
		"MASK": &cfg.Mask, "FAST_MODE": &cfg.FastMode, "PREFER_IPV6": &cfg.PreferIPv6,
		"PROXY_PROTOCOL": &cfg.ProxyProtocol, "IGNORE_TIME_SKEW": &cfg.IgnoreTimeSkew,
		"METRICS_EXPORT_LINKS": &cfg.MetricsExportLinks, "MODES_CLASSIC": &cfg.Modes.Classic,
		"MODES_SECURE": &cfg.Modes.Secure, "MODES_TLS": &cfg.Modes.TLS,
	}
	strs := map[string]*string{
		"TLS_DOMAIN": &cfg.TLSDomain, "MASK_HOST": &cfg.MaskHost, "MY_DOMAIN": &cfg.MyDomain,
		"LISTEN_ADDR_IPV4": &cfg.ListenAddrIPv4, "LISTEN_ADDR_IPV6": &cfg.ListenAddrIPv6,
		"LISTEN_UNIX_SOCK": &cfg.ListenUnixSock, "METRICS_LISTEN_ADDR_IPV4": &cfg.MetricsListenAddrV4,
		"METRICS_LISTEN_ADDR_IPV6": &cfg.MetricsListenAddrV6, "METRICS_PREFIX": &cfg.MetricsPrefix,
		"LOG_LEVEL": &cfg.LogLevel,
	}
	for _, key := range sec.Keys() {
		name := key.Name()
		if dest, ok := ints[name]; ok {
			*dest, err = key.Int()
		} else if dest, ok := bools[name]; ok {
			*dest, err = key.Bool()
		} else if dest, ok := strs[name]; ok {
			*dest = strings.Trim(strings.TrimSpace(key.String()), `"'`)
		} else {
			switch name {
			case "SECRET":
				for _, s := range strings.Split(key.String(), ",") {
					s = strings.TrimSpace(s)
					if !secretHexRe.MatchString(s) {
						return nil, fmt.Errorf("SECRET 必须由 32 位十六进制密钥组成")
					}
					s = strings.ToLower(s)
					if s == "00000000000000000000000000000000" || s == "00000000000000000000000000000001" || s == "0123456789abcdef0123456789abcdef" {
						return nil, fmt.Errorf("SECRET 是公开的示例密钥，请先运行 mtpgo -s 生成随机密钥")
					}
					b, _ := hex.DecodeString(s)
					for _, old := range cfg.Secrets {
						if hex.EncodeToString(old) == s {
							return nil, fmt.Errorf("SECRET 不能重复")
						}
					}
					cfg.Secrets = append(cfg.Secrets, b)
				}
			case "AD_TAG":
				cfg.ADTag, err = hex.DecodeString(strings.TrimSpace(key.String()))
				if err == nil && len(cfg.ADTag) != 0 && len(cfg.ADTag) != 16 {
					err = fmt.Errorf("必须是 32 位十六进制字符")
				}
			case "METRICS_WHITELIST":
				cfg.MetricsWhitelist = nil
				for _, s := range strings.Split(key.String(), ",") {
					if s = strings.TrimSpace(s); s != "" {
						cfg.MetricsWhitelist = append(cfg.MetricsWhitelist, s)
					}
				}
			case "CLIENT_IPS_LEN":
				return nil, fmt.Errorf("CLIENT_IPS_LEN 从未实现，已移除，请删除此配置项")
			default:
				return nil, fmt.Errorf("未知配置项 %s", name)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s 无效: %w", name, err)
		}
	}
	if len(f.Sections()) > 1 {
		return nil, fmt.Errorf("配置项必须放在默认节中")
	}
	if len(cfg.Secrets) == 0 {
		return nil, fmt.Errorf("缺少 SECRET，请运行 mtpgo -s 生成随机密钥")
	}
	cfg.LogLevel = strings.ToLower(cfg.LogLevel)
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("LOG_LEVEL 必须是 debug/info/warn/error")
	}
	for name, value := range map[string]int{"PORT": cfg.Port, "MASK_PORT": cfg.MaskPort} {
		if value < 1 || value > 65535 {
			return nil, fmt.Errorf("%s 超出 1-65535", name)
		}
	}
	if cfg.MetricsPort < 0 || cfg.MetricsPort > 65535 {
		return nil, fmt.Errorf("METRICS_PORT 超出 0-65535")
	}
	for name, value := range ints {
		if strings.Contains(name, "TIMEOUT") || strings.Contains(name, "PERIOD") || name == "CLIENT_KEEPALIVE" {
			if *value < 1 || *value > 86400 {
				return nil, fmt.Errorf("%s 必须为 1-86400 秒", name)
			}
		}
	}
	if cfg.ReplayCheckLen < 0 || cfg.ReplayCheckLen > 1<<20 {
		return nil, fmt.Errorf("REPLAY_CHECK_LEN 必须为 0-1048576")
	}
	if !cfg.Modes.Classic && !cfg.Modes.Secure && !cfg.Modes.TLS {
		return nil, fmt.Errorf("至少启用一种代理模式")
	}
	if cfg.MaskHost == "" {
		cfg.MaskHost = cfg.TLSDomain
	}
	if !validHost(cfg.TLSDomain) || !validHost(cfg.MaskHost) || (cfg.MyDomain != "" && !validHost(cfg.MyDomain)) {
		return nil, fmt.Errorf("TLS_DOMAIN、MASK_HOST 或 MY_DOMAIN 不是有效主机名/IP")
	}
	for name, value := range map[string]string{"LISTEN_ADDR_IPV4": cfg.ListenAddrIPv4, "METRICS_LISTEN_ADDR_IPV4": cfg.MetricsListenAddrV4} {
		if value != "" && (net.ParseIP(value) == nil || net.ParseIP(value).To4() == nil) {
			return nil, fmt.Errorf("%s 必须是 IPv4 地址或空字符串", name)
		}
	}
	for name, value := range map[string]string{"LISTEN_ADDR_IPV6": cfg.ListenAddrIPv6, "METRICS_LISTEN_ADDR_IPV6": cfg.MetricsListenAddrV6} {
		if value != "" && (net.ParseIP(value) == nil || net.ParseIP(value).To4() != nil) {
			return nil, fmt.Errorf("%s 必须是 IPv6 地址或空字符串", name)
		}
	}
	if cfg.ListenAddrIPv4 == "" && cfg.ListenAddrIPv6 == "" && cfg.ListenUnixSock == "" {
		return nil, fmt.Errorf("至少设置一个监听地址")
	}
	if cfg.ListenUnixSock != "" && !filepath.IsAbs(cfg.ListenUnixSock) {
		return nil, fmt.Errorf("LISTEN_UNIX_SOCK 必须为绝对路径")
	}
	if cfg.MetricsPort != 0 && cfg.MetricsListenAddrV4 == "" && cfg.MetricsListenAddrV6 == "" {
		return nil, fmt.Errorf("启用指标时必须设置指标监听地址")
	}
	if cfg.MetricsPrefix != "" && !metricPrefixRe.MatchString(cfg.MetricsPrefix) {
		return nil, fmt.Errorf("METRICS_PREFIX 无效")
	}
	for _, s := range cfg.MetricsWhitelist {
		if net.ParseIP(s) == nil {
			if _, _, err := net.ParseCIDR(s); err != nil {
				return nil, fmt.Errorf("METRICS_WHITELIST 无效: %s", s)
			}
		}
	}
	cfg.UseMiddleProxy = len(cfg.ADTag) == 16
	return cfg, nil
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Listener changes cannot be applied atomically without dropping existing binds.
func ValidateReload(old, next *Config) error {
	if old.Port != next.Port || old.ListenAddrIPv4 != next.ListenAddrIPv4 || old.ListenAddrIPv6 != next.ListenAddrIPv6 || old.ListenUnixSock != next.ListenUnixSock || old.MetricsPort != next.MetricsPort || old.MetricsListenAddrV4 != next.MetricsListenAddrV4 || old.MetricsListenAddrV6 != next.MetricsListenAddrV6 {
		return fmt.Errorf("监听端口/地址变更需要重启；本次重载未应用任何变更")
	}
	return nil
}

// RunPeriodic responds to cancellation and new immutable configuration snapshots.
// A one-second check bounds reload latency without resetting the task's timer on
// every tick. initial=false is useful for delayed statistics output.
func RunPeriodic(ctx context.Context, a *AtomicConfig, interval func(*Config) time.Duration, initial bool, task func(context.Context, *Config)) {
	cfg := a.Get()
	next := time.Now().Add(interval(cfg))
	if initial {
		task(ctx, cfg)
		next = time.Now().Add(interval(cfg))
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			latest := a.Get()
			if latest != cfg || !time.Now().Before(next) {
				cfg = latest
				task(ctx, cfg)
				next = time.Now().Add(interval(cfg))
			}
		}
	}
}

func ParseArgs() string {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	defaultConfig := filepath.Join(filepath.Dir(exe), "config.ini")
	var cfgPath string
	var genSecret, showHelp, showVersion, checkConfig bool
	flag.StringVar(&cfgPath, "c", defaultConfig, "配置文件路径")
	flag.StringVar(&cfgPath, "config", defaultConfig, "配置文件路径")
	flag.BoolVar(&genSecret, "s", false, "生成随机密钥")
	flag.BoolVar(&genSecret, "secret", false, "生成随机密钥")
	flag.BoolVar(&showHelp, "h", false, "显示帮助")
	flag.BoolVar(&showHelp, "help", false, "显示帮助")
	flag.BoolVar(&showVersion, "v", false, "查看版本")
	flag.BoolVar(&showVersion, "version", false, "查看版本")
	flag.BoolVar(&checkConfig, "check", false, "验证配置后退出，不连接网络")
	flag.Parse()
	if showHelp {
		flag.Usage()
		os.Exit(0)
	}
	if showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}
	if genSecret {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(b))
		os.Exit(0)
	}
	if checkConfig {
		if _, err := LoadConfig(cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("配置有效")
		os.Exit(0)
	}
	return cfgPath
}
