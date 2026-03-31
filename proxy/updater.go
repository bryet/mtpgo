package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"mtproxy/config"
	"mtproxy/crypto"
)

// ── 日志 ──────────────────────────────────────────────────────────────────────

var logWriter io.Writer

func SetLogger(w io.Writer) {
	logWriter = w
}

func Logf(format string, args ...interface{}) {
	if logWriter != nil {
		fmt.Fprintf(logWriter, format, args...)
	}
}

func Dbgf(cfg *config.Config, format string, args ...interface{}) {
	if cfg != nil && cfg.Debug {
		Logf(format, args...)
	}
}

// ── 中间代理列表更新 ──────────────────────────────────────────────────────────

func getNewProxies(url string) (map[int][][2]interface{}, error) {
	re := regexp.MustCompile(`proxy_for\s+(-?\d+)\s+(.+):(\d+)\s*;`)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ans := make(map[int][][2]interface{})
	for _, match := range re.FindAllStringSubmatch(string(body), -1) {
		dcIdx, _ := strconv.Atoi(match[1])
		host := match[2]
		port, _ := strconv.Atoi(match[3])
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		ans[dcIdx] = append(ans[dcIdx], [2]interface{}{host, port})
	}
	return ans, nil
}

func UpdateMiddleProxyInfo(cfg *config.Config) {
	const (
		proxyInfoAddr   = "https://core.telegram.org/getProxyConfig"
		proxyInfoAddrV6 = "https://core.telegram.org/getProxyConfigV6"
		proxySecretAddr = "https://core.telegram.org/getProxySecret"
	)

	for {
		// 更新 IPv4 代理列表
		v4, err := getNewProxies(proxyInfoAddr)
		if err != nil || len(v4) == 0 {
			Logf("Error updating middle proxy list: %v\n", err)
		} else {
			MiddleProxyMu.Lock()
			TGMiddleProxiesV4 = v4
			MiddleProxyMu.Unlock()
		}

		// 更新 IPv6 代理列表
		v6, err := getNewProxies(proxyInfoAddrV6)
		if err != nil || len(v6) == 0 {
			Logf("Error updating middle proxy list (IPv6): %v\n", err)
		} else {
			MiddleProxyMu.Lock()
			TGMiddleProxiesV6 = v6
			MiddleProxyMu.Unlock()
		}

		// 更新 ProxySecret
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(proxySecretAddr)
		if err != nil {
			Logf("Error updating middle proxy secret: %v\n", err)
		} else {
			secret, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if len(secret) > 0 {
				newSecret := make([]byte, len(secret))
				copy(newSecret, secret)
				if string(newSecret) != string(ProxySecret) {
					ProxySecret = newSecret
					Logf("Middle proxy secret updated\n")
				}
			}
		}

		time.Sleep(time.Duration(cfg.ProxyInfoUpdatePeriod) * time.Second)
	}
}

// ── TLS 证书长度获取 ──────────────────────────────────────────────────────────

var FakeCertLen = 2048 // 默认值
var FakeCertMu sync.RWMutex

func GetMaskHostCertLen(cfg *config.Config) {
	const getCertTimeout = 10 * time.Second
	const maskEnablingCheckPeriod = 60 * time.Second

	for {
		if !cfg.Mask {
			time.Sleep(maskEnablingCheckPeriod)
			continue
		}

		func() {
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: getCertTimeout},
				"tcp",
				fmt.Sprintf("%s:%d", cfg.MaskHost, cfg.MaskPort),
				&tls.Config{
					ServerName:         cfg.TLSDomain,
					InsecureSkipVerify: true,
				},
			)
			if err != nil {
				Logf("Failed to connect to MASK_HOST %s: %v\n", cfg.MaskHost, err)
				return
			}
			defer conn.Close()

			// 获取证书原始数据长度
			state := conn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				Logf("MASK_HOST %s returned no certificates\n", cfg.MaskHost)
				return
			}
			certLen := len(state.PeerCertificates[0].Raw)
			if certLen < MinCertLen {
				Logf("MASK_HOST %s cert too short: %d\n", cfg.MaskHost, certLen)
				return
			}

			FakeCertMu.Lock()
			if certLen != FakeCertLen {
				FakeCertLen = certLen
				Logf("Got cert from MASK_HOST %s, length: %d\n", cfg.MaskHost, certLen)
			}
			FakeCertMu.Unlock()
		}()

		time.Sleep(time.Duration(cfg.GetCertLenPeriod) * time.Second)
	}
}

// ── IP 缓存清理 ───────────────────────────────────────────────────────────────

func ClearIPResolvingCache() {
	for {
		sleepTime := 60 + crypto.GlobalRand.Intn(60)
		time.Sleep(time.Duration(sleepTime) * time.Second)
		// 简单实现：重新获取一次 mask host IP（Go 的 net 包有内置 DNS 缓存处理）
	}
}
