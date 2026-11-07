package stats

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"mtproxy/config"
)

// ── Prometheus metrics 格式输出 ───────────────────────────────────────────────

type metricEntry struct {
	name   string
	mtype  string
	desc   string
	labels map[string]string
	val    interface{}
}

func makeMetricsPkt(entries []metricEntry, prefix string) string {
	var sb strings.Builder
	usedNames := map[string]bool{}

	for _, e := range entries {
		fullName := prefix + e.name
		if !usedNames[fullName] {
			fmt.Fprintf(&sb, "# HELP %s %s\n", fullName, e.desc)
			fmt.Fprintf(&sb, "# TYPE %s %s\n", fullName, e.mtype)
			usedNames[fullName] = true
		}

		if len(e.labels) > 0 {
			var tags []string
			valStr := fmt.Sprintf("%v", e.val)
			for k, v := range e.labels {
				if k == "val" {
					valStr = v
					continue
				}
				escaped := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(v)
				tags = append(tags, fmt.Sprintf(`%s="%s"`, k, escaped))
			}
			sort.Strings(tags)
			fmt.Fprintf(&sb, "%s{%s} %s\n", fullName, strings.Join(tags, ","), valStr)
		} else {
			fmt.Fprintf(&sb, "%s %v\n", fullName, e.val)
		}
	}
	return sb.String()
}

// ── IP 白名单（支持精确 IP 和 CIDR 两种格式）────────────────────────────────

// ipAllowed 检查 clientIP 是否在白名单内。
// 支持两种格式：
//   - 精确 IP：如 "127.0.0.1"、"::1"
//   - CIDR 网段：如 "127.0.0.0/8"、"10.0.0.0/8"、"::1/128"
func ipAllowed(clientIP string, whitelist []string) bool {
	parsed := net.ParseIP(clientIP)
	if parsed == nil {
		return false
	}
	for _, entry := range whitelist {
		if strings.Contains(entry, "/") {
			// CIDR 匹配
			_, network, err := net.ParseCIDR(entry)
			if err == nil && network.Contains(parsed) {
				return true
			}
		} else {
			// 精确 IP 匹配
			if ip := net.ParseIP(entry); ip != nil && ip.Equal(parsed) {
				return true
			}
		}
	}
	return false
}

// ── metrics handler ───────────────────────────────────────────────────────────

func MetricsHandler(cfg *config.Config, proxyLinks []map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		// 白名单检查（支持精确 IP 和 CIDR）
		if !ipAllowed(clientIP, cfg.MetricsWhitelist) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		var entries []metricEntry

		uptime := time.Since(ProxyStartTime).Seconds()
		entries = append(entries, metricEntry{"uptime", "gauge", "proxy uptime", nil, uptime})
		entries = append(entries, metricEntry{"connects_bad", "counter", "rejected incoming handshakes", nil,
			atomic.LoadInt64(&GlobalStats.ConnectsBad)})
		entries = append(entries, metricEntry{"connects_all", "counter", "incoming connects", nil,
			atomic.LoadInt64(&GlobalStats.ConnectsAll)})
		entries = append(entries, metricEntry{"handshake_timeouts", "counter", "number of timed out handshakes", nil,
			atomic.LoadInt64(&GlobalStats.HandshakeTimeouts)})

		// 代理链接信息
		if cfg.MetricsExportLinks {
			for _, link := range proxyLinks {
				labels := map[string]string{
					"link": link["link"],
					"val":  "1",
				}
				entries = append(entries, metricEntry{"proxy_link_info", "gauge", "the proxy link info", labels, 1})
			}
		}

		// 连接时长桶
		GlobalStats.Mu.RLock()
		bucketStart := 0.0
		for _, bucket := range DurationBuckets {
			bucketEnd := fmt.Sprintf("%v", bucket)
			if bucket == DurationBuckets[len(DurationBuckets)-1] {
				bucketEnd = "+Inf"
			}
			labels := map[string]string{
				"bucket": fmt.Sprintf("%v-%s", bucketStart, bucketEnd),
				"val":    fmt.Sprintf("%d", GlobalStats.ConnectsByDuration[bucket]),
			}
			entries = append(entries, metricEntry{"connects_by_duration", "counter", "connects by duration", labels, GlobalStats.ConnectsByDuration[bucket]})
			bucketStart = bucket
		}
		GlobalStats.Mu.RUnlock()

		// 每个 secret 的统计
		type userMetric struct {
			name    string
			mtype   string
			desc    string
			statKey string
		}
		userMetrics := []userMetric{
			{"user_connects", "counter", "user connects", "connects"},
			{"user_connects_curr", "gauge", "current user connects", "curr_connects"},
			{"user_octets", "counter", "octets proxied for user", "octets_total"},
			{"user_msgs", "counter", "msgs proxied for user", "msgs_total"},
			{"user_octets_from", "counter", "octets from user", "octets_from_client"},
			{"user_octets_to", "counter", "octets to user", "octets_to_client"},
			{"user_msgs_from", "counter", "msgs from user", "msgs_from_client"},
			{"user_msgs_to", "counter", "msgs to user", "msgs_to_client"},
		}

		GlobalStats.Mu.RLock()
		for secretHex, st := range GlobalStats.SecretStats {
			for _, um := range userMetrics {
				var val int64
				switch um.statKey {
				case "connects":
					val = atomic.LoadInt64(&st.Connects)
				case "curr_connects":
					val = atomic.LoadInt64(&st.CurrConnects)
				case "octets_total":
					val = atomic.LoadInt64(&st.OctetsFromClt) + atomic.LoadInt64(&st.OctetsToClt)
				case "msgs_total":
					val = atomic.LoadInt64(&st.MsgsFromClt) + atomic.LoadInt64(&st.MsgsToClt)
				case "octets_from_client":
					val = atomic.LoadInt64(&st.OctetsFromClt)
				case "octets_to_client":
					val = atomic.LoadInt64(&st.OctetsToClt)
				case "msgs_from_client":
					val = atomic.LoadInt64(&st.MsgsFromClt)
				case "msgs_to_client":
					val = atomic.LoadInt64(&st.MsgsToClt)
				}
				labels := map[string]string{
					"user": UserID(secretHex),
					"val":  fmt.Sprintf("%d", val),
				}
				entries = append(entries, metricEntry{um.name, um.mtype, um.desc, labels, val})
			}
		}
		GlobalStats.Mu.RUnlock()

		body := makeMetricsPkt(entries, cfg.MetricsPrefix)

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}
}

// NewMetricsHandler derives links from the same immutable snapshot as its
// whitelist and export flag, so reloaded secrets are never paired with old links.
func NewMetricsHandler(a *config.AtomicConfig, links func(*config.Config) []map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := a.Get()
		var current []map[string]string
		if cfg.MetricsExportLinks {
			current = links(cfg)
		}
		MetricsHandler(cfg, current)(w, r)
	}
}

// Bind synchronously so startup errors are visible. Return servers for shutdown.
func StartMetricsServer(a *config.AtomicConfig, links func(*config.Config) []map[string]string, logf func(string, ...interface{})) ([]*http.Server, error) {
	cfg := a.Get()
	if cfg.MetricsPort == 0 {
		return nil, nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", NewMetricsHandler(a, links))
	var servers []*http.Server
	var listeners []net.Listener
	for _, item := range []struct{ network, host string }{{"tcp4", cfg.MetricsListenAddrV4}, {"tcp6", cfg.MetricsListenAddrV6}} {
		if item.host == "" {
			continue
		}
		addr := net.JoinHostPort(item.host, fmt.Sprint(cfg.MetricsPort))
		ln, err := net.Listen(item.network, addr)
		if err != nil {
			for _, ln := range listeners {
				ln.Close()
			}
			return nil, fmt.Errorf("metrics listen %s: %w", addr, err)
		}
		listeners = append(listeners, ln)
		servers = append(servers, &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second})
	}
	for i, server := range servers {
		ln := listeners[i]
		go func() {
			if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logf("Metrics server error: %v\n", err)
			}
		}()
	}
	return servers, nil
}
func ShutdownMetrics(ctx context.Context, servers []*http.Server) {
	for _, s := range servers {
		if err := s.Shutdown(ctx); err != nil {
			s.Close()
		}
	}
}
