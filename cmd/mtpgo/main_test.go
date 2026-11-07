package main

import (
	"context"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mtproxy/config"
	"mtproxy/proxy"
)

func TestBuildProxyLinks(t *testing.T) {
	c := config.DefaultConfig()
	c.Secrets = [][]byte{make([]byte, 16)}
	c.MyDomain = "2001:db8::1"
	links := buildProxyLinks(c)
	if len(links) != 3 {
		t.Fatal(links)
	}
	for _, l := range links {
		u, err := url.Parse(l["link"])
		if err != nil || u.Query().Get("server") != c.MyDomain || u.Query().Get("port") != "3256" {
			t.Fatal(l, err)
		}
		if !strings.HasPrefix(u.RawQuery, "server=2001%3Adb8%3A%3A1&port=3256&secret=") {
			t.Fatalf("unexpected query order or encoding: %s", u.RawQuery)
		}
	}
}
func TestBuildProxyLinksTLSExample(t *testing.T) {
	secret, err := hex.DecodeString("a059801be0015893a27af64a7106761c")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.MyDomain = "192.168.2.1"
	cfg.Port = 54164
	cfg.Secrets = [][]byte{secret}
	cfg.Modes = config.Modes{TLS: true}
	cfg.TLSDomain = "itunes.apple.com"
	links := buildProxyLinks(cfg)
	want := "https://t.me/proxy?server=192.168.2.1&port=54164&secret=eea059801be0015893a27af64a7106761c6974756e65732e6170706c652e636f6d"
	if len(links) != 1 || links[0]["link"] != want {
		t.Fatalf("unexpected TLS link: %v", links)
	}
}
func TestPublicIPResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			w.WriteHeader(500)
			return
		}
		if r.URL.Path == "/huge" {
			w.Write([]byte(strings.Repeat("x", 200)))
			return
		}
		w.Write([]byte("192.0.2.1\n"))
	}))
	defer srv.Close()
	if got := getFirstIPConcurrent(srv.Client(), []string{srv.URL + "/bad", srv.URL + "/huge", srv.URL + "/good"}); got != "192.0.2.1" {
		t.Fatal(got)
	}
}
func TestUnixListenerDoesNotDeleteFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "socket")
	os.WriteFile(p, []byte("keep"), 0600)
	c := config.DefaultConfig()
	c.ListenAddrIPv4 = ""
	c.ListenAddrIPv6 = ""
	c.ListenUnixSock = p
	var wg sync.WaitGroup
	g := &connectionGroup{conns: make(map[net.Conn]struct{})}
	ln := startServers(config.NewAtomicConfig(c), g, &wg)
	if len(ln) != 0 {
		t.Fatal("unexpected listener")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "keep" {
		t.Fatal("removed existing file")
	}
}
func TestConnectionGroupShutdown(t *testing.T) {
	g := &connectionGroup{conns: make(map[net.Conn]struct{})}
	a, b := net.Pipe()
	defer b.Close()
	if !g.add(a) {
		t.Fatal("add")
	}
	g.closeAll()
	g.done(a)
	g.wg.Wait()
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	if g.add(c) {
		t.Fatal("accepted after shutdown")
	}
}
func TestBackgroundTasksCancel(t *testing.T) {
	c := config.DefaultConfig()
	c.Mask = false
	c.UseMiddleProxy = false
	a := config.NewAtomicConfig(c)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { proxy.UpdateMiddleProxyInfo(ctx, a); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("updater did not cancel")
	}
}
