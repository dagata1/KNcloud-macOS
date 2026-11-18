package main

import (
	"errors"
	"net/http"
	"testing"

	"v2rayN-win11/internal/bootproxy"
)

func TestPanelAttemptPlan(t *testing.T) {
	eq := func(a, b []bool) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	if p := panelAttemptPlan(false, false); !eq(p, []bool{false}) {
		t.Errorf("no boot: %v", p)
	}
	if p := panelAttemptPlan(false, true); !eq(p, []bool{false, true}) {
		t.Errorf("boot enabled: %v", p)
	}
	if p := panelAttemptPlan(true, true); !eq(p, []bool{true, false}) {
		t.Errorf("boot active: %v", p)
	}
}

func TestBootSessionStopsProxy(t *testing.T) {
	old := startBootProxy
	defer func() { startBootProxy = old }()
	startBootProxy = func() (*bootproxy.Proxy, error) {
		return bootproxy.Start(bootproxy.Options{Password: "x", Upstreams: []string{"127.0.0.1:1"}})
	}
	a := &App{}
	outer := a.bootSession()
	inner := a.bootSession()
	if _, err := a.bootClient(); err != nil {
		t.Fatal(err)
	}
	if a.bootPort() == 0 {
		t.Fatal("boot proxy not running")
	}
	inner()
	inner() // idempotent
	if a.bootPort() == 0 {
		t.Fatal("stopped while another session is active")
	}
	outer()
	if a.bootPort() != 0 {
		t.Fatal("boot proxy still running after last session")
	}
}

func TestWithPanelRetryFallsBackToBoot(t *testing.T) {
	old := startBootProxy
	defer func() { startBootProxy = old }()
	started := 0
	startBootProxy = func() (*bootproxy.Proxy, error) {
		started++
		return bootproxy.Start(bootproxy.Options{Password: "x", Upstreams: []string{"127.0.0.1:1"}})
	}
	if !bootproxy.Enabled() {
		t.Skip("boot node not configured in this build")
	}
	a := &App{}
	defer a.bootSession()()
	calls := 0
	err := withPanelRetry(a, func(c *http.Client) error {
		calls++
		if calls == 1 {
			return &panelNetError{errors.New("direct down")}
		}
		if a.bootPort() == 0 {
			t.Error("second attempt did not use boot proxy")
		}
		return nil
	})
	if err != nil || calls != 2 || started != 1 {
		t.Fatalf("err=%v calls=%d started=%d", err, calls, started)
	}
	// HTTP 层错误不重试、不启用引导
	b := &App{}
	calls = 0
	_ = withPanelRetry(b, func(c *http.Client) error { calls++; return errors.New("login failed: bad password") })
	if calls != 1 || b.bootPort() != 0 {
		t.Fatalf("non-network error retried: calls=%d", calls)
	}
}
