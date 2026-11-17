package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeProxy is a plain HTTP proxy stand-in: it sees the absolute-form
// request the client sends to its local HTTP proxy.
func fakeProxy(t *testing.T, status int, got chan<- *http.Request) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Clone(r.Context())
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return p
}

func TestDevicePingViaLocalProxy(t *testing.T) {
	got := make(chan *http.Request, 1)
	port := fakeProxy(t, http.StatusNoContent, got)
	if err := devicePingVia(port); err != nil {
		t.Fatal(err)
	}
	r := <-got
	if r.Method != "GET" || r.Host != devicePingHost || r.URL.Path != "/v1/ping" || r.URL.Query().Get("id") != deviceID() {
		t.Fatalf("request %s %s host %s", r.Method, r.URL, r.Host)
	}
	if r.Header.Get(hdrDeviceID) != deviceID() || r.Header.Get("Authorization") != "" {
		t.Fatalf("headers %v", r.Header)
	}
	// only the node's 204 counts
	port = fakeProxy(t, http.StatusServiceUnavailable, make(chan *http.Request, 1))
	if err := devicePingVia(port); err == nil {
		t.Fatal("503 not reported")
	}
	// local proxy not listening: fails fast, silently for the caller
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().(*net.TCPAddr).Port
	l.Close()
	start := time.Now()
	if err := devicePingVia(dead); err == nil || time.Since(start) > devicePingTimeout+time.Second {
		t.Fatalf("dead proxy: %v after %s", err, time.Since(start))
	}
}

func TestDevicePingSchedule(t *testing.T) {
	var sent []int
	old := devicePingSend
	devicePingSend = func(port int) { sent = append(sent, port) }
	defer func() { devicePingSend = old }()

	a := &App{}
	a.coreRunning = true
	a.liveHTTPPort.Store(10809)
	var st devicePingState
	t0 := time.Unix(1_700_000_000, 0)
	a.coreNodeID = "n-sg"
	if a.devicePingTick(&st, t0, "a1") {
		t.Fatal("pinged while logged out")
	}
	a.account = AccountInfo{LoggedIn: true, Domain: "https://p", AuthToken: "tok"}
	a.coreNodeID = ""
	if a.devicePingTick(&st, t0, "a1") {
		t.Fatal("pinged without a node (direct-only core)")
	}
	a.coreNodeID = "n-sg"
	if !a.devicePingTick(&st, t0, "a1") {
		t.Fatal("no ping after connecting")
	}
	if a.devicePingTick(&st, t0.Add(5*time.Minute), "a1") {
		t.Fatal("pinged again before the interval")
	}
	a.coreNodeID = "n-jp" // node switch
	if !a.devicePingTick(&st, t0.Add(5*time.Minute+5*time.Second), "a1") {
		t.Fatal("node switch not pinged")
	}
	if a.devicePingTick(&st, t0.Add(5*time.Minute+8*time.Second), "a2") {
		t.Fatal("network change within the min gap pinged")
	}
	if !a.devicePingTick(&st, t0.Add(5*time.Minute+20*time.Second), "a2") {
		t.Fatal("network change not pinged")
	}
	a.tunEgressIface = "以太网"
	if !a.devicePingTick(&st, t0.Add(6*time.Minute), "a2") {
		t.Fatal("TUN on not pinged")
	}
	if !a.devicePingTick(&st, t0.Add(17*time.Minute), "a2") {
		t.Fatal("periodic ping missing")
	}
	a.liveHTTPPort.Store(0)
	if a.devicePingTick(&st, t0.Add(40*time.Minute), "a2") {
		t.Fatal("pinged with the core stopped")
	}
	if len(sent) != 5 || sent[0] != 10809 {
		t.Fatalf("sent %v", sent)
	}
}

// The reserved host is the first rule and goes to the node in every policy
// (incl. 全局直连 and TUN), so it is never resolved / dialled directly; a
// direct-only core (no node) has no such rule.
func TestDevicePingRouteFirst(t *testing.T) {
	node := NodeItem{ID: "s", Protocol: "Shadowsocks", Address: "1.2.3.4", Port: 8388, Method: "aes-128-gcm", UUID: "pw", Network: "tcp"}
	for _, mode := range []string{"bypass-cn", "direct", "global", "proxy-cn"} {
		for _, tun := range []string{"", "以太网"} {
			a := &App{routingMode: mode, tunEgressIface: tun, settings: AppSettings{SocksPort: 10808, HttpPort: 10809, DnsServers: "1.1.1.1"}}
			rules := coreRulesOf(t, a, node)
			if len(rules) == 0 || rules[0].OutboundTag != "proxy" || len(rules[0].Domain) != 1 || rules[0].Domain[0] != "full:"+devicePingHost {
				t.Fatalf("%s tun=%q: first rule %+v", mode, tun, rules)
			}
		}
	}
	a := &App{routingMode: "global", settings: AppSettings{SocksPort: 10808, HttpPort: 10809, DnsServers: "1.1.1.1"}}
	cfg, err := a.buildDirectCoreConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, devicePingHost) {
		t.Fatal("direct-only config routes the reserved host")
	}
}
