// Package bootproxy 登录引导：官网接口直连（或经内核）都连不上时，在 127.0.0.1 的随机端口
// 临时起一个只给本程序官网 HTTP 客户端用的 HTTP CONNECT 代理，经内置的引导节点
// （Shadowsocks，见 config.go）出站。不碰 TUN / 系统代理 / 内核，不需要管理员权限；
// 登录 / 拉订阅结束就关掉。纯标准库 + x/crypto，可在 Linux 上跑单测。
package bootproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DialTimeout 连引导节点的超时（每个候选地址）。
var DialTimeout = 8 * time.Second

// MaxLifetime 引导代理最长存活时间（调用方忘了 Close 也会自己关）。
var MaxLifetime = 3 * time.Minute

// Proxy 一个运行中的引导代理。
type Proxy struct {
	ln       net.Listener
	allow    func(host string) bool
	dial     func(ctx context.Context) (net.Conn, error)
	password string

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	timer  *time.Timer
}

// Options 启动参数（零值用 config.go 里的引导节点）。
type Options struct {
	// Allow 允许经引导代理访问的目标主机（nil = DefaultAllow）。
	Allow func(host string) bool
	// Upstreams 引导节点候选地址，按顺序尝试（nil = Host:Port，再 [FallbackIP]:Port）。
	Upstreams []string
	Password  string
}

// DefaultAllow 只放行 kncloud.top 及其子域（与节点「仅允许」一致；其他目标节点也会拒绝）。
func DefaultAllow(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == "kncloud.top" || strings.HasSuffix(h, ".kncloud.top")
}

// Upstreams 默认候选：先域名（AAAA），DNS 失败 / 连不上再用写死的 IPv6。
func Upstreams() []string {
	var out []string
	if Host != "" {
		out = append(out, net.JoinHostPort(Host, Port))
	}
	if FallbackIP != "" {
		out = append(out, net.JoinHostPort(FallbackIP, Port))
	}
	return out
}

// Start 在 127.0.0.1 随机端口启动引导代理。
func Start(opt Options) (*Proxy, error) {
	if opt.Password == "" {
		opt.Password = Password
	}
	if opt.Password == "" || strings.HasPrefix(opt.Password, "__") {
		return nil, errors.New("bootproxy: not configured")
	}
	if opt.Allow == nil {
		opt.Allow = DefaultAllow
	}
	ups := opt.Upstreams
	if ups == nil {
		ups = Upstreams()
	}
	if len(ups) == 0 {
		return nil, errors.New("bootproxy: no upstream")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln, allow: opt.Allow, password: opt.Password, conns: map[net.Conn]struct{}{}}
	var lastGood struct {
		sync.Mutex
		i int
	}
	p.dial = func(ctx context.Context) (net.Conn, error) {
		lastGood.Lock()
		start := lastGood.i
		lastGood.Unlock()
		var errs []string
		for k := 0; k < len(ups); k++ {
			i := (start + k) % len(ups)
			d := net.Dialer{Timeout: DialTimeout}
			c, err := d.DialContext(ctx, "tcp", ups[i])
			if err == nil {
				lastGood.Lock()
				lastGood.i = i
				lastGood.Unlock()
				return c, nil
			}
			errs = append(errs, err.Error())
		}
		return nil, errors.New("bootproxy: boot node unreachable: " + strings.Join(errs, "; "))
	}
	p.timer = time.AfterFunc(MaxLifetime, func() { p.Close() })
	go p.serve()
	log.Printf("[boot] 登录引导代理已启动 127.0.0.1:%d", p.Port())
	return p, nil
}

// Port 本地监听端口。
func (p *Proxy) Port() int { return p.ln.Addr().(*net.TCPAddr).Port }

// URL 给 http.ProxyURL 用的代理地址。
func (p *Proxy) URL() string { return "http://127.0.0.1:" + strconv.Itoa(p.Port()) }

// Close 停止监听并断开所有连接（可重复调用）。
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.timer.Stop()
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	log.Printf("[boot] 登录引导代理已关闭")
	return p.ln.Close()
}

// Closed 是否已关闭。
func (p *Proxy) Closed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *Proxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
	c.Close()
}

func (p *Proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		if !p.track(c) {
			c.Close()
			return
		}
		go p.handle(c)
	}
}

func (p *Proxy) handle(c net.Conn) {
	defer p.untrack(c)
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	target := req.Host
	host, _, err := net.SplitHostPort(target)
	if err != nil || !p.allow(host) {
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	addr, err := socksAddr(target)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*DialTimeout+time.Second)
	up, err := p.dial(ctx)
	cancel()
	if err != nil {
		log.Printf("[boot] %v", err)
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	if !p.track(up) {
		up.Close()
		return
	}
	defer p.untrack(up)
	ss := newSSConn(up, p.password)
	if _, err := ss.Write(addr); err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		// 客户端在 CONNECT 后可能已经把 TLS ClientHello 一起发来（在 br 的缓冲里）
		if n := br.Buffered(); n > 0 {
			b, _ := br.Peek(n)
			if _, err := ss.Write(b); err != nil {
				done <- struct{}{}
				return
			}
			br.Discard(n)
		}
		io.Copy(ss, c)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(c, ss)
		done <- struct{}{}
	}()
	<-done
}
