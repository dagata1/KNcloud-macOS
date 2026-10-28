package bootproxy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEVPBytesToKey(t *testing.T) {
	// shadowsocks-libev / go-shadowsocks2 give the same key for "foobar"
	got := hex.EncodeToString(evpBytesToKey("foobar", 32))
	want := "3858f62230ac3c915f300c664312c63f568378529614d22ddb49237d2f60bfdf"
	if got != want {
		t.Fatalf("key %s want %s", got, want)
	}
}

func TestSocksAddr(t *testing.T) {
	b, _ := socksAddr("www.kncloud.top:443")
	if b[0] != 3 || int(b[1]) != len("www.kncloud.top") || binary.BigEndian.Uint16(b[len(b)-2:]) != 443 {
		t.Fatalf("%x", b)
	}
	b, _ = socksAddr("[2001:db8::1]:80")
	if b[0] != 4 || len(b) != 19 {
		t.Fatalf("%x", b)
	}
	if _, err := socksAddr("x:0"); err == nil {
		t.Fatal("port 0 accepted")
	}
}

// fakeSS 用同一个 ssConn 实现服务端（协议对称），把目标地址统一改连 target。
func fakeSS(t *testing.T, password, target string, seen *atomic.Value) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				s := newSSConn(c, password)
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(s, hdr); err != nil || hdr[0] != 3 {
					return
				}
				host := make([]byte, int(hdr[1])+2)
				if _, err := io.ReadFull(s, host); err != nil {
					return
				}
				seen.Store(string(host[:len(host)-2]) + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(host[len(host)-2:]))))
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(up, s)
				io.Copy(s, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func proxyClient(p *Proxy) *http.Client {
	pu, _ := url.Parse(p.URL())
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
}

func TestProxyEndToEnd(t *testing.T) {
	big := bytes.Repeat([]byte("kncloud"), 20000) // > 0x3FFF, several chunks
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Length", strconv.Itoa(len(big)+len(body)))
		w.Write(big)
		w.Write(body)
	}))
	defer srv.Close()
	var seen atomic.Value
	ss := fakeSS(t, "pw-123", strings.TrimPrefix(srv.URL, "http://"), &seen)
	// 第一个候选连不上，应回退到第二个
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	p, err := Start(Options{Password: "pw-123", Upstreams: []string{deadAddr, ss}, Allow: func(h string) bool { return h == "api.kncloud.top" }})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// CONNECT 隧道里跑明文 HTTP（相当于 TLS 的位置），验证双向数据
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(p.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT api.kncloud.top:443 HTTP/1.1\r\nHost: api.kncloud.top:443\r\n\r\nPOST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	resp, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(resp, []byte("HTTP/1.1 200 Connection Established\r\n\r\nHTTP/1.1 200")) {
		t.Fatalf("bad response (%d bytes): %q", len(resp), resp[:120])
	}
	if !bytes.Contains(resp, append(append([]byte{}, big...), "hello"...)) {
		t.Fatal("body corrupted")
	}
	if got := seen.Load(); got != "api.kncloud.top:443" {
		t.Fatalf("server saw target %v", got)
	}

	// 不在允许列表的目标在本地就被拒
	r, err := proxyClient(p).Get("https://www.google.com/")
	if err == nil {
		r.Body.Close()
		t.Fatal("google allowed")
	}

	// Close 后端口不再接受连接
	p.Close()
	if c2, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p.Port()), time.Second); err == nil {
		c2.Close()
		t.Fatal("still listening after Close")
	}
}

func TestWrongPasswordFails(t *testing.T) {
	var seen atomic.Value
	ss := fakeSS(t, "right", "127.0.0.1:1", &seen)
	p, err := Start(Options{Password: "wrong", Upstreams: []string{ss}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	r, err := proxyClient(p).Get("https://api.kncloud.top/")
	if err == nil {
		r.Body.Close()
		t.Fatal("request succeeded with wrong password")
	}
	if seen.Load() != nil {
		t.Fatal("server decoded a target with the wrong password")
	}
}

func TestDefaultAllow(t *testing.T) {
	for h, want := range map[string]bool{"kncloud.top": true, "WWW.KNcloud.top": true, "api.kncloud.top.": true, "evilkncloud.top": false, "kncloud.top.evil.com": false, "google.com": false} {
		if DefaultAllow(h) != want {
			t.Errorf("%s: %v", h, !want)
		}
	}
}

func TestNotConfigured(t *testing.T) {
	old := Password
	Password = "__BOOT_PASSWORD__"
	defer func() { Password = old }()
	if _, err := Start(Options{}); err == nil {
		t.Fatal("started without password")
	}
}

func TestMaxLifetime(t *testing.T) {
	old := MaxLifetime
	MaxLifetime = 50 * time.Millisecond
	defer func() { MaxLifetime = old }()
	p, err := Start(Options{Password: "x", Upstreams: []string{"127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if !p.Closed() {
		t.Fatal("not closed after MaxLifetime")
	}
}
