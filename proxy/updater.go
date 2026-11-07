package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mtproxy/config"
)

var proxySecretMu sync.RWMutex

func GetProxySecret() []byte {
	proxySecretMu.RLock()
	defer proxySecretMu.RUnlock()
	return append([]byte(nil), ProxySecret...)
}
func setProxySecret(s []byte) {
	proxySecretMu.Lock()
	defer proxySecretMu.Unlock()
	ProxySecret = append([]byte(nil), s...)
}

const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

var logWriter io.Writer = io.Discard
var logMu sync.Mutex
var logLevel atomic.Int32

func init() { logLevel.Store(LevelInfo) }
func SetLogger(w io.Writer) {
	logMu.Lock()
	defer logMu.Unlock()
	if w == nil {
		w = io.Discard
	}
	logWriter = w
}
func SetLogLevel(level string) {
	v := int32(LevelInfo)
	switch level {
	case "debug":
		v = LevelDebug
	case "warn":
		v = LevelWarn
	case "error":
		v = LevelError
	}
	logLevel.Store(v)
}
func logWrite(format string, args ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintf(logWriter, format, args...)
}
func Debugf(cfg *config.Config, f string, a ...interface{}) {
	if cfg != nil && logLevel.Load() <= LevelDebug {
		logWrite("[DEBUG] "+f, a...)
	}
}
func Infof(f string, a ...interface{}) {
	if logLevel.Load() <= LevelInfo {
		logWrite("[INFO]  "+f, a...)
	}
}
func Warnf(f string, a ...interface{}) {
	if logLevel.Load() <= LevelWarn {
		logWrite("[WARN]  "+f, a...)
	}
}
func Errorf(f string, a ...interface{}) {
	if logLevel.Load() <= LevelError {
		logWrite("[ERROR] "+f, a...)
	}
}
func Logf(f string, a ...interface{})                   { Infof(f, a...) }
func Dbgf(c *config.Config, f string, a ...interface{}) { Debugf(c, f, a...) }

// Validate status and bound every external response before parsing/publishing it.
func fetchBody(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return b, nil
}

var proxyLineRe = regexp.MustCompile(`proxy_for\s+(-?\d+)\s+([^\s;]+):(\d+)\s*;`)

func parseProxyList(body []byte) (map[int][][2]interface{}, error) {
	ans := make(map[int][][2]interface{})
	for _, m := range proxyLineRe.FindAllStringSubmatch(string(body), -1) {
		dc, err := strconv.Atoi(m[1])
		if err != nil || dc == 0 {
			return nil, fmt.Errorf("invalid DC index: %q", m[1])
		}
		// Telegram also publishes special DCs (for example ±203). This
		// proxy handles only ±1–±5; skip other DCs rather than rejecting
		// the entire official list and retaining stale fallback nodes.
		if dc < -5 || dc > 5 {
			continue
		}
		host := strings.Trim(m[2], "[]")
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("invalid proxy IP")
		}
		port, err := strconv.Atoi(m[3])
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid proxy port")
		}
		ans[dc] = append(ans[dc], [2]interface{}{host, port})
	}
	if len(ans) == 0 {
		return nil, fmt.Errorf("no supported DCs in proxy list")
	}
	return ans, nil
}
func UpdateMiddleProxyInfo(ctx context.Context, a *config.AtomicConfig) {
	client := &http.Client{Timeout: 10 * time.Second}
	config.RunPeriodic(ctx, a, func(c *config.Config) time.Duration { return time.Duration(c.ProxyInfoUpdatePeriod) * time.Second }, true, func(ctx context.Context, c *config.Config) {
		if !c.UseMiddleProxy {
			return
		}
		for _, v6 := range []bool{false, true} {
			url := "https://core.telegram.org/getProxyConfig"
			if v6 {
				url += "V6"
			}
			body, err := fetchBody(ctx, client, url, 1<<20)
			var proxies map[int][][2]interface{}
			if err == nil {
				proxies, err = parseProxyList(body)
			}
			if err != nil {
				Warnf("middle proxy list update failed (v6=%v): %v\n", v6, err)
				continue
			}
			MiddleProxyMu.Lock()
			if v6 {
				TGMiddleProxiesV6 = proxies
			} else {
				TGMiddleProxiesV4 = proxies
			}
			MiddleProxyMu.Unlock()
		}
		body, err := fetchBody(ctx, client, "https://core.telegram.org/getProxySecret", 256)
		if err != nil || len(body) != 128 {
			Warnf("middle proxy secret update rejected (length=%d): %v\n", len(body), err)
			return
		}
		if !bytes.Equal(body, GetProxySecret()) {
			setProxySecret(body)
			Infof("Middle proxy secret updated\n")
		}
	})
}

var FakeCertLen = 2048
var FakeCertMu sync.RWMutex

func GetMaskHostCertLen(ctx context.Context, a *config.AtomicConfig) {
	config.RunPeriodic(ctx, a, func(c *config.Config) time.Duration { return time.Duration(c.GetCertLenPeriod) * time.Second }, true, func(ctx context.Context, c *config.Config) {
		if !c.Mask || !c.Modes.TLS {
			return
		}
		ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TGConnectTimeout)*time.Second)
		defer cancel()
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Duration(c.TGConnectTimeout) * time.Second}, Config: &tls.Config{ServerName: c.TLSDomain, MinVersion: tls.VersionTLS12}}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(c.MaskHost, fmt.Sprint(c.MaskPort)))
		if err != nil {
			Warnf("MASK_HOST certificate lookup failed: %v\n", err)
			return
		}
		defer conn.Close()
		state := conn.(*tls.Conn).ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return
		}
		n := len(state.PeerCertificates[0].Raw)
		if n < MinCertLen || n > 16384-64 {
			Warnf("MASK_HOST certificate length out of range: %d\n", n)
			return
		}
		FakeCertMu.Lock()
		FakeCertLen = n
		FakeCertMu.Unlock()
	})
}

// No artificial DNS refresh loop: Go's resolver does not expose such a cache.
// Every new outbound dial resolves the current host normally.
