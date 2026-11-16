package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDeviceIDPersisted(t *testing.T) {
	dir := t.TempDir()
	id := loadOrCreateDeviceID(dir)
	if !uuidV4Re.MatchString(id) {
		t.Fatalf("not a uuid v4: %q", id)
	}
	if again := loadOrCreateDeviceID(dir); again != id {
		t.Fatalf("id changed: %q -> %q", id, again)
	}
	_ = os.WriteFile(filepath.Join(dir, deviceIDFile), []byte("garbage"), 0600)
	if n := loadOrCreateDeviceID(dir); n == id || !uuidV4Re.MatchString(n) {
		t.Fatalf("invalid file not replaced: %q", n)
	}
}

func subServer(t *testing.T, status int, body string, gotHdr *http.Header) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotHdr != nil {
			*gotHdr = r.Header.Clone()
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGetSubscribeDeviceURL(t *testing.T) {
	var h http.Header
	srv := subServer(t, 200, `{"data":{"subscribe_url":"https://x/generic","device_subscribe_url":"https://x/device","email":"a@b"}}`, &h)
	_, _, _, _, _, sub, _, dev, err := v2boardGetSubscribe(srv.URL, "tok")
	if err != nil || sub != "https://x/device" || !dev {
		t.Fatalf("got %q dev=%v err=%v", sub, dev, err)
	}
	if h.Get(hdrDeviceID) == "" || h.Get(hdrPlatform) == "" || h.Get(hdrClientVersion) == "" {
		t.Fatalf("device headers missing: %v", h)
	}

	srv = subServer(t, 200, `{"data":{"subscribe_url":"https://x/generic"}}`, nil)
	_, _, _, _, _, sub, _, dev, err = v2boardGetSubscribe(srv.URL, "tok")
	if err != nil || sub != "https://x/generic" || dev {
		t.Fatalf("old panel: got %q dev=%v err=%v", sub, dev, err)
	}
}

func TestGetSubscribeErrors(t *testing.T) {
	cases := []struct {
		status  int
		body    string
		session bool
		panel   string
	}{
		{403, `{"message":"未登录或登陆已过期"}`, true, ""},
		{403, ``, true, ""},
		{401, `{"message":"x"}`, true, ""},
		{403, `{"message":"设备数量已达上限（3 台）"}`, false, "设备数量已达上限（3 台）"},
		{429, `{"message":"too many devices"}`, false, "too many devices"},
	}
	for _, c := range cases {
		srv := subServer(t, c.status, c.body, nil)
		_, _, _, _, _, _, _, _, err := v2boardGetSubscribe(srv.URL, "tok")
		var pe *panelMsgError
		switch {
		case c.session && err != errTokenInvalid:
			t.Errorf("%d %s: want session expired, got %v", c.status, c.body, err)
		case c.panel != "" && (!errors.As(err, &pe) || pe.msg != c.panel):
			t.Errorf("%d %s: want panel msg, got %v", c.status, c.body, err)
		}
	}
}

func TestLoginPanelMessage(t *testing.T) {
	var h http.Header
	srv := subServer(t, 403, `{"message":"设备数量已达上限"}`, &h)
	_, err := v2boardLogin(srv.URL, "a@b", "p")
	var pe *panelMsgError
	if !errors.As(err, &pe) || pe.msg != "设备数量已达上限" {
		t.Fatalf("got %v", err)
	}
	if h.Get(hdrDeviceID) == "" {
		t.Fatal("login without device id header")
	}
}

func TestAccountErrToast(t *testing.T) {
	if got := accountErrToast(&panelMsgError{status: 403, msg: "m"}); got != "m" {
		t.Fatal(got)
	}
	if got := accountErrToast(errDeviceRemoved); got != "此设备已在面板中移除，请重新登录" {
		t.Fatal(got)
	}
}
