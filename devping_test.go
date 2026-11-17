package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDevicePingRequest(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.Write([]byte(`{"data":{"ip":"127.0.0.1","family":4,"recorded":true}}`))
	}))
	defer srv.Close()
	// a bogus system / environment proxy must not be used (direct request)
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	if err := devicePingOnce(srv.URL+"/", "tok123", "tcp4", ""); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Method != "POST" || got.URL.Path != devicePingPath {
		t.Fatalf("request %+v", got)
	}
	if got.Header.Get("Authorization") != "tok123" || got.Header.Get(hdrDeviceID) != deviceID() || got.Header.Get(hdrPlatform) == "" {
		t.Fatalf("headers %v", got.Header)
	}
	// IPv6 to an IPv4-only server fails (silently for the caller), never falls back to IPv4
	if err := devicePingOnce(srv.URL, "tok123", "tcp6", ""); err == nil {
		t.Fatal("tcp6 to 127.0.0.1 succeeded")
	}
}

func TestDevicePingStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	if err := devicePingOnce(srv.URL, "t", "tcp4", ""); err == nil {
		t.Fatal("429 not reported")
	}
	srv.Close()
	start := time.Now()
	if err := devicePingOnce(srv.URL, "t", "tcp4", ""); err == nil || time.Since(start) > devicePingTimeout+time.Second {
		t.Fatalf("unreachable panel: %v after %s", err, time.Since(start))
	}
}

func TestDevicePingSchedule(t *testing.T) {
	var sent []string
	old := devicePingSend
	devicePingSend = func(domain, token, egress string, v6 bool) { sent = append(sent, domain+"|"+token+"|"+egress) }
	defer func() { devicePingSend = old }()

	a := &App{}
	a.coreRunning = true
	var st devicePingState
	t0 := time.Unix(1_700_000_000, 0)
	if a.devicePingTick(&st, t0, "n1") {
		t.Fatal("pinged while logged out")
	}
	a.account = AccountInfo{LoggedIn: true, Domain: "https://p", AuthToken: "tok"}
	if !a.devicePingTick(&st, t0, "n1") {
		t.Fatal("no ping after login")
	}
	if a.devicePingTick(&st, t0.Add(5*time.Minute), "n1") {
		t.Fatal("pinged again before the interval")
	}
	if a.devicePingTick(&st, t0.Add(30*time.Second), "n2") {
		t.Fatal("network change within the min gap pinged")
	}
	if !a.devicePingTick(&st, t0.Add(6*time.Minute), "n2") {
		t.Fatal("network change not pinged")
	}
	a.tunEgressIface = "以太网"
	if !a.devicePingTick(&st, t0.Add(8*time.Minute), "n2") {
		t.Fatal("TUN on not pinged")
	}
	if !a.devicePingTick(&st, t0.Add(19*time.Minute), "n2") {
		t.Fatal("periodic ping missing")
	}
	a.coreRunning = false
	if a.devicePingTick(&st, t0.Add(40*time.Minute), "n2") {
		t.Fatal("pinged with core stopped")
	}
	if len(sent) != 3+1 || sent[2] != "https://p|tok|以太网" {
		t.Fatalf("sent %v", sent)
	}
}

func TestDevicePingGlobalV6(t *testing.T) {
	for s, want := range map[string]bool{"2409:8a00::1": true, "fdfe:dcba:9876::1": false, "fe80::1": false, "1.2.3.4": false} {
		if got := isGlobalV6(net.ParseIP(s)); got != want {
			t.Errorf("isGlobalV6(%s) = %v", s, got)
		}
	}
}
