package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSecret = "6dcaf91a861ee45c5a218c465d52a307"

func loadText(t *testing.T, text string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(p)
}
func TestLoadConfigAllFields(t *testing.T) {
	text := `SECRET = ` + testSecret + `
CLIENT_HANDSHAKE_TIMEOUT = 2
TG_CONNECT_TIMEOUT = 3
TG_READ_TIMEOUT = 4
CLIENT_KEEPALIVE = 5
CLIENT_ACK_TIMEOUT = 6
PROXY_INFO_UPDATE_PERIOD = 7
GET_CERT_LEN_PERIOD = 8
STATS_PRINT_PERIOD = 9
AD_TAG = 1234567890abcdef1234567890abcdef
METRICS_WHITELIST = 192.0.2.0/24, ::1
LOG_LEVEL = WARN
`
	c, err := loadText(t, text)
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientHandshakeTimeout != 2 || c.TGConnectTimeout != 3 || c.TGReadTimeout != 4 || c.ClientKeepalive != 5 || c.ClientAckTimeout != 6 || c.ProxyInfoUpdatePeriod != 7 || c.GetCertLenPeriod != 8 || c.StatsPrintPeriod != 9 || !c.UseMiddleProxy || c.LogLevel != "warn" {
		t.Fatalf("unexpected config: %+v", c)
	}
	if len(c.MetricsWhitelist) != 2 || len(c.Secrets) != 1 {
		t.Fatal("slices not parsed")
	}
}
func TestRejectInvalidConfig(t *testing.T) {
	for _, text := range []string{"", "SECRET=", "SECRET=00000000000000000000000000000000", "SECRET=garbage", "SECRET=" + testSecret + ",bad", "SECRET=" + testSecret + "," + testSecret} {
		if _, err := loadText(t, text); err == nil {
			t.Errorf("accepted secret config %q", text)
		}
	}
	for _, line := range []string{"PORT=0", "MASK_PORT=65536", "METRICS_PORT=-1", "MASK=garbage", "TG_READ_TIMEOUT=0", "TG_CONNECT_TIMEOUT=86401", "CLIENT_ACK_TIMEOUT=-1", "STATS_PRINT_PERIOD=0", "GET_CERT_LEN_PERIOD=0", "REPLAY_CHECK_LEN=-1", "AD_TAG=aa", "LOG_LEVEL=trace", "METRICS_WHITELIST=bad", "TLS_DOMAIN=a/b", "TLS_DOMAIN=-example.com", "LISTEN_ADDR_IPV4=::1", "LISTEN_ADDR_IPV6=127.0.0.1", "LISTEN_UNIX_SOCK=relative.sock", "METRICS_PREFIX=a b", "CLIENT_IPS_LEN=20", "UNKNOWN=1", "MODES_CLASSIC=false\nMODES_SECURE=false\nMODES_TLS=false"} {
		t.Run(strings.ReplaceAll(line, "\n", "/"), func(t *testing.T) {
			if _, err := loadText(t, "SECRET="+testSecret+"\n"+line); err == nil {
				t.Fatalf("accepted %q", line)
			}
		})
	}
}
func TestTemplateRequiresSecret(t *testing.T) {
	b, err := os.ReadFile("../config.example.ini")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(b), "SECRET = 00000000000000000000000000000000", "SECRET = "+testSecret, 1)
	cfg, err := loadText(t, text)
	if err != nil {
		t.Fatal(err)
	}
	defaults := DefaultConfig()
	if cfg.Port != 8443 || cfg.Modes.Classic || !cfg.Modes.Secure || cfg.Modes.TLS {
		t.Fatalf("unexpected simplified template settings: %+v", cfg)
	}
	if cfg.TGConnectTimeout != defaults.TGConnectTimeout || cfg.TGReadTimeout != defaults.TGReadTimeout || cfg.ClientHandshakeTimeout != defaults.ClientHandshakeTimeout || cfg.ReplayCheckLen != defaults.ReplayCheckLen || cfg.MetricsPort != defaults.MetricsPort {
		t.Fatal("omitted advanced settings did not retain defaults")
	}
}
func TestValidateReload(t *testing.T) {
	a := DefaultConfig()
	b := *a
	b.LogLevel = "debug"
	if err := ValidateReload(a, &b); err != nil {
		t.Fatal(err)
	}
	b.Port++
	if ValidateReload(a, &b) == nil {
		t.Fatal("accepted changed port")
	}
	b = *a
	b.MetricsListenAddrV4 = "0.0.0.0"
	if ValidateReload(a, &b) == nil {
		t.Fatal("accepted changed metrics address")
	}
}
func TestAtomicConfigConcurrent(t *testing.T) {
	a := NewAtomicConfig(DefaultConfig())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				a.Set(DefaultConfig())
				_ = a.Get().Port
			}
		}()
	}
	wg.Wait()
}
func TestPeriodicReloadAndCancel(t *testing.T) {
	a := NewAtomicConfig(DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan *Config, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunPeriodic(ctx, a, func(*Config) time.Duration { return time.Hour }, true, func(_ context.Context, c *Config) { calls <- c })
	}()
	<-calls
	next := DefaultConfig()
	next.LogLevel = "debug"
	a.Set(next)
	select {
	case got := <-calls:
		if got != next {
			t.Fatal("stale config")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reload not observed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("task did not cancel")
	}
}
