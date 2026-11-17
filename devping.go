package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// 设备上报（面板「我的设备」按设备统计流量）——经当前节点，不直连官网。
//
// 节点按「用户 + 来源 IP」上报流量，面板按设备出现过的 IP 把流量归到设备上。
// 本程序访问官网（登录、拉订阅）一般经本地代理 / 其他代理出去，面板看到的不是
// 连节点时的那个 IP，流量就落进「未识别设备」。
//
// 所以连上节点后，本程序经自己的本地 HTTP 代理（即正常代理路由，不绕开）请求保留
// 主机 http://device.kncloud.internal/v1/ping（带本机设备 ID）。这个请求随代理
// 协议加密送到当前节点，knode 在节点上直接应答（不会出站，也不解析域名），记下这条
// 代理连接认证出的用户和它看到的来源 IP，再经节点与面板之间已有的控制通道上报。
// 官网域名不出现在本机的任何直连请求里（之前的直连上报每 10 分钟从国内直连官网，
// 会暴露域名，已取消）。
//
// 内核配置里有一条最先匹配的路由：device.kncloud.internal → proxy（见 core.go），
// 任何策略（含全局直连、TUN）下都走当前节点，不会经 direct 出站做 DNS 解析。
//
// 时机：连上 / 切换节点后（约 10 秒内）、网络变化（本机地址 / TUN 出口 / 账户变化）、
// 以及每 10 分钟；未登录、内核未运行或没有节点（直连配置）时不发。失败一律静默。
const (
	devicePingHost    = "device.kncloud.internal"
	devicePingURL     = "http://" + devicePingHost + "/v1/ping"
	devicePingEvery   = 10 * time.Minute
	devicePingMinGap  = 10 * time.Second
	devicePingCheck   = 10 * time.Second
	devicePingFirst   = 15 * time.Second
	devicePingTimeout = 10 * time.Second
)

// devicePingState 上一次上报时的状态（只在 devicePingLoop 的 goroutine 里用）。
type devicePingState struct {
	key  string // 账户 + 节点 + 本机地址 + TUN 出口；变了就尽快重报
	last time.Time
}

// devicePingSend 实际发送（单测替换）：经本地 HTTP 代理 127.0.0.1:port。
var devicePingSend = func(port int) { _ = devicePingVia(port) }

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

// devicePingTick 判断是否该上报，该报就发（同步，最多 devicePingTimeout）。
func (a *App) devicePingTick(st *devicePingState, now time.Time, addrs string) bool {
	if !a.rlockWithin(2 * time.Second) {
		return false
	}
	acc := a.account
	egress := a.tunEgressIface
	node := a.coreNodeID
	running := a.coreRunning || a.tunRunning
	a.mu.RUnlock()
	port := int(a.liveHTTPPort.Load())
	if !acc.LoggedIn || acc.AuthToken == "" || !running || node == "" || port <= 0 {
		st.key = "" // 再次登录 / 连上节点后立即上报
		return false
	}
	key := strings.Join([]string{acc.Domain, acc.AuthToken, node, addrs, egress}, "\x00")
	due := st.last.IsZero() || now.Sub(st.last) >= devicePingEvery || (key != st.key && now.Sub(st.last) >= devicePingMinGap)
	if !due {
		return false
	}
	st.key, st.last = key, now
	devicePingSend(port)
	return true
}

// devicePingVia 经本地 HTTP 代理发一次上报；节点应答 204 才算成功。
func devicePingVia(port int) error {
	proxy := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)}
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(proxy),
		ResponseHeaderTimeout: 8 * time.Second,
		DisableKeepAlives:     true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Timeout: devicePingTimeout, Transport: tr}
	id := deviceID()
	req, err := http.NewRequest("GET", devicePingURL+"?id="+url.QueryEscape(id), nil)
	if err != nil {
		return err
	}
	req.Header.Set(hdrDeviceID, id)
	req.Header.Set("User-Agent", devicePingUA())
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("device report: HTTP %d", resp.StatusCode)
	}
	return nil
}

// devicePingRule 内核路由里最先匹配的一条：保留主机一律走 proxy（有节点时）。
func devicePingRule() ruleObj {
	return ruleObj{Type: "field", Domain: []string{"full:" + devicePingHost}, OutboundTag: "proxy"}
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
