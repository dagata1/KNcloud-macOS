package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// 设备直连上报（面板「我的设备」按设备统计流量）。
//
// 节点按「用户 + 来源 IP」上报流量，面板按设备出现过的 IP 把流量归到设备上。
// 但本程序访问官网（登录、拉订阅）一般经本地代理 / 其他代理出去，面板看到的不是
// 连节点时的那个 IP（比如国内 IPv6），流量就落进「未识别设备」。
//
// 所以登录后定时向官网发一个很小的上报：POST /api/v1/user/device/ping，
// 带登录凭证（Authorization）与设备登记头（X-KN-Device-*），并且
//   - 绕开本程序自己的代理：Transport 不设代理（不读系统代理 / 环境变量）；
//     TUN 接管时 socket 绑定物理网卡（与内核到节点的出站同一张网卡），不进 TUN；
//   - IPv4、IPv6 各发一次（tcp4 / tcp6，没有公网 IPv6 地址就不发 IPv6）：
//     连节点走哪个协议族不确定，两个都报，面板两个都记。
//
// 时机：登录后约 15 秒、网络变化（本机地址 / TUN 出口 / 账户变化，间隔至少 70 秒）、
// 以及每 10 分钟。失败（官网直连不通、超时、面板拒绝）一律静默，不提示、不重试，
// 下个周期再说。面板对同一设备同一地址每分钟只收一次，并按账户限频。
const (
	devicePingPath    = "/api/v1/user/device/ping"
	devicePingEvery   = 10 * time.Minute
	devicePingMinGap  = 70 * time.Second
	devicePingCheck   = 30 * time.Second
	devicePingFirst   = 15 * time.Second
	devicePingTimeout = 10 * time.Second
)

// devicePingState 上一次上报时的状态（只在 devicePingLoop 的 goroutine 里用）。
type devicePingState struct {
	account string // 官网地址 + 凭证（换账户 / 重新登录立即上报）
	addrs   string // 本机地址指纹（换网络立即上报）
	egress  string // TUN 物理出口（开关 TUN 立即上报）
	last    time.Time
}

// devicePingSend 实际发送（单测替换）。
var devicePingSend = devicePingAll

func (a *App) devicePingLoop() {
	ticker := time.NewTicker(devicePingCheck)
	defer ticker.Stop()
	first := time.NewTimer(devicePingFirst)
	defer first.Stop()
	var st devicePingState
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-first.C:
		case <-ticker.C:
		}
		a.devicePingTick(&st, time.Now(), localAddrFingerprint())
	}
}

// devicePingTick 判断是否该上报，该报就发（同步，最多两次 devicePingTimeout）。
func (a *App) devicePingTick(st *devicePingState, now time.Time, addrs string) bool {
	if !a.rlockWithin(2 * time.Second) {
		return false
	}
	acc := a.account
	egress := a.tunEgressIface
	running := a.coreRunning || a.tunRunning
	a.mu.RUnlock()
	if !acc.LoggedIn || acc.AuthToken == "" || acc.Domain == "" || !running {
		st.account = "" // 再次登录 / 内核恢复后立即上报
		return false
	}
	key := acc.Domain + "\x00" + acc.AuthToken
	changed := key != st.account || addrs != st.addrs || egress != st.egress
	due := st.last.IsZero() || now.Sub(st.last) >= devicePingEvery || (changed && now.Sub(st.last) >= devicePingMinGap)
	if !due {
		return false
	}
	st.account, st.addrs, st.egress, st.last = key, addrs, egress, now
	devicePingSend(acc.Domain, acc.AuthToken, egress, hasGlobalIPv6())
	return true
}

// devicePingAll IPv4（总是）与 IPv6（有公网 IPv6 地址时）各发一次；错误全部忽略。
func devicePingAll(domain, token, egress string, v6 bool) {
	_ = devicePingOnce(domain, token, "tcp4", egress)
	if v6 {
		_ = devicePingOnce(domain, token, "tcp6", egress)
	}
}

// devicePingOnce 用指定协议族（tcp4 / tcp6）直连官网发一次上报。
// egress 非空（TUN 接管中）时 socket 绑定该物理网卡。
func devicePingOnce(domain, token, network, egress string) error {
	d := &net.Dialer{Timeout: 8 * time.Second}
	if egress != "" {
		if ifc, err := net.InterfaceByName(egress); err == nil {
			d.Control = devicePingBindControl(uint32(ifc.Index))
		}
	}
	tr := &http.Transport{
		Proxy: nil, // 直连：不经本程序的本地代理，也不读系统代理 / 环境变量
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		DisableKeepAlives:     true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Timeout: devicePingTimeout, Transport: tr}
	req, err := http.NewRequest("POST", strings.TrimRight(domain, "/")+devicePingPath, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	req.Header.Set("User-Agent", devicePingUA())
	setDeviceHeaders(req)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("device ping: HTTP %d", resp.StatusCode)
	}
	return nil
}

func devicePingUA() string {
	if devicePlatform() == "macos" {
		return "KNcloud-macOS/" + appVersion
	}
	return "KNcloud-WIN/" + appVersion
}

// isGlobalV6 公网 IPv6（2000::/3）；ULA（TUN 网卡的 fd..）、链路本地不算。
func isGlobalV6(ip net.IP) bool {
	return ip.To4() == nil && len(ip) == net.IPv6len && ip[0]&0xe0 == 0x20
}

// localAddrs 本机已启用、非回环网卡上的 IPv4 与公网 IPv6 地址（排序后）。
func localAddrs() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipn.IP.To4(); ip4 != nil {
				if !ip4.IsLinkLocalUnicast() {
					out = append(out, ip4.String())
				}
			} else if isGlobalV6(ipn.IP) {
				out = append(out, ipn.IP.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

// localAddrFingerprint 本机地址指纹（变了说明换了网络）。
func localAddrFingerprint() string {
	sum := sha256.Sum256([]byte(strings.Join(localAddrs(), ",")))
	return hex.EncodeToString(sum[:8])
}

func hasGlobalIPv6() bool {
	for _, s := range localAddrs() {
		if strings.Contains(s, ":") {
			return true
		}
	}
	return false
}
