package stats

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"mtproxy/config"
)

func TestWhitelist(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		list []string
		want bool
	}{{"::1", []string{"0:0:0:0:0:0:0:1"}, true}, {"192.0.2.3", []string{"192.0.2.0/24"}, true}, {"198.51.100.1", []string{"192.0.2.0/24"}, false}, {"127.0.0.1", nil, false}} {
		if ipAllowed(tc.ip, tc.list) != tc.want {
			t.Fatal(tc)
		}
	}
}
func TestMetricsEscaping(t *testing.T) {
	b := makeMetricsPkt([]metricEntry{{"test", "gauge", "test", map[string]string{"a": "quote\"slash\\newline\n", "z": "z"}, 1}}, "mtproxy_")
	if !strings.Contains(b, `a="quote\"slash\\newline\n",z="z"`) {
		t.Fatal(b)
	}
}
func TestMetricsReload(t *testing.T) {
	c := config.DefaultConfig()
	c.MetricsWhitelist = []string{"192.0.2.1"}
	c.MetricsExportLinks = true
	c.MyDomain = "old"
	a := config.NewAtomicConfig(c)
	handler := NewMetricsHandler(a, func(c *config.Config) []map[string]string { return []map[string]string{{"link": c.MyDomain}} })
	request := func(ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://localhost/", nil)
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	if w := request("192.0.2.1"); w.Code != 200 || !strings.Contains(w.Body.String(), `link="old"`) {
		t.Fatal(w)
	}
	next := *c
	next.MyDomain = "new"
	next.MetricsWhitelist = []string{"198.51.100.1"}
	a.Set(&next)
	if request("192.0.2.1").Code != http.StatusForbidden {
		t.Fatal("old whitelist retained")
	}
	if w := request("198.51.100.1"); w.Code != 200 || !strings.Contains(w.Body.String(), `link="new"`) || strings.Contains(w.Body.String(), `link="old"`) {
		t.Fatal(w)
	}
}
func TestMetricsReloadConcurrent(t *testing.T) {
	c := config.DefaultConfig()
	a := config.NewAtomicConfig(c)
	h := NewMetricsHandler(a, func(c *config.Config) []map[string]string { return nil })
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				next := config.DefaultConfig()
				next.MetricsPrefix = fmt.Sprintf("p%d_", j)
				a.Set(next)
				r := httptest.NewRequest("GET", "http://localhost/", nil)
				r.RemoteAddr = "127.0.0.1:1"
				h(httptest.NewRecorder(), r)
			}
		}()
	}
	wg.Wait()
}
func TestUserIDDoesNotExposeSecret(t *testing.T) {
	a, b := "01234567aaaaaaaaaaaaaaaaaaaaaaaa", "01234567bbbbbbbbbbbbbbbbbbbbbbbb"
	if UserID(a) == UserID(b) || strings.Contains(UserID(a), "01234567") {
		t.Fatal("user labels expose/collide on secret prefixes")
	}
}
