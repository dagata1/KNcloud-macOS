package main

// tunnode6.go —— TUN 模式下双栈节点的地址族选择与 IPv6 防回环 /128 路由。
//
// 规则与系统代理模式一致（Xray 按域名拨号时 Go 解析器的默认行为）：
//   - 本机有 IPv6 出口且节点有 AAAA：走 IPv6；
//   - 否则走 IPv4。
//
// 走 IPv6 时：节点的 IPv6 写一条 /128 走物理网卡（TUN 挂了 2000::/3，不写会被吸回 TUN
// 形成回环），Shadowsocks/SOCKS 出站钉在这个 IPv6 上（Xray 的 UDP 拨号不受
// sockopt.interface 约束，钉 IP 才能保证 UDP 也走 /128）。节点的 IPv4 /32 照常写，
// 互不影响。

import (
	"net"
	"strings"
	"sync"
	"time"
)

// tunNodeV6 TUN 选中的节点 IPv6 及其物理出口（/128 路由的内容）。

type tunNodeV6 struct {
	IP      net.IP
	IfIndex uint32
	NextHop net.IP // 物理网卡 IPv6 默认网关（通常是 fe80:: 链路本地地址）；nil = on-link
}

func (v *tunNodeV6) sameRoute(o *tunNodeV6) bool {
	if v == nil || o == nil {
		return v == o
	}
	return v.IP.Equal(o.IP) && v.IfIndex == o.IfIndex && v.NextHop.Equal(o.NextHop)
}

// isGlobalUnicastV6 只接受 2000::/3 全球单播（排除链路本地、ULA、IPv4 映射等）。

func isGlobalUnicastV6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	ip16 := ip.To16()
	return ip16 != nil && ip16[0]&0xe0 == 0x20
}

func filterValidIPv6s(ips []net.IP) []net.IP {
	var out []net.IP
	for _, ip := range ips {
		if isGlobalUnicastV6(ip) {
			out = append(out, ip.To16())
			if len(out) >= 4 {
				break
			}
		}
	}
	return out
}

var nodeIP6Cache = struct {
	sync.Mutex
	m map[string]nodeIPCacheEntry
}{m: map[string]nodeIPCacheEntry{}}

// lookupNodeIPv6sCached 解析节点 AAAA（带缓存与时间上限，失败返回 nil、不写缓存）。

func lookupNodeIPv6sCached(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return filterValidIPv6s([]net.IP{ip})
	}
	key := strings.ToLower(host)
	nodeIP6Cache.Lock()
	if e, ok := nodeIP6Cache.m[key]; ok && time.Now().Before(e.until) && len(e.ips) > 0 {
		ips := e.ips
		nodeIP6Cache.Unlock()
		return ips
	}
	nodeIP6Cache.Unlock()

	res := make(chan []net.IP, 1)
	go func() {
		ips := filterValidIPv6s(mustLookupIPs(host))
		if len(ips) > 0 {
			nodeIP6Cache.Lock()
			nodeIP6Cache.m[key] = nodeIPCacheEntry{ips: ips, until: time.Now().Add(nodeIPCacheTTL)}
			nodeIP6Cache.Unlock()
		}
		res <- ips
	}()
	select {
	case ips := <-res:
		return ips
	case <-time.After(nodeLookupBudget):
		vlog("resolve node %s AAAA: timed out after %s", host, nodeLookupBudget)
		return nil
	}
}

// listRoutes6 枚举系统 IPv6 路由。

// sockaddrIn6Addr 从 SOCKADDR_INET（AF_INET6）取地址：family(2) port(2) flowinfo(4) addr(16) scope(4)。

// physV6Exit 本机的物理 IPv6 出口：一条不在 TUN/原生 TAP 上的 ::/0 默认路由，且该网卡

// 有全球单播 IPv6 地址。没有就说明本机没有 IPv6 出口。TUN 运行中也能正确返回。

func ifaceHasGlobalV6(ifIdx uint32) bool {
	ifc, err := net.InterfaceByIndex(int(ifIdx))
	if err != nil || ifc.Flags&net.FlagUp == 0 {
		return false
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && isGlobalUnicastV6(n.IP) {
			return true
		}
	}
	return false
}

// pickTunNodeV6 双栈选择：本机有 IPv6 出口且节点有 AAAA 时返回要走的 IPv6，否则 nil（走 IPv4）。

func pickTunNodeV6(host string, tunIdx uint32) *tunNodeV6 {
	ifIdx, hop, ok := physV6Exit(tunIdx)
	if !ok {
		return nil
	}
	ips := lookupNodeIPv6sCached(host)
	if len(ips) == 0 {
		return nil
	}
	return &tunNodeV6{IP: ips[0], IfIndex: ifIdx, NextHop: hop}
}

// hasNodeV6Route 回读：IPv6 路由表里是否有这条 /128（netsh 参数错误时退出码仍为 0）。

// addNodeV6Route 写节点 IPv6 /128 走物理网卡（已存在视为成功）。

// removeNodeV6Route 撤节点 IPv6 /128（不存在视为成功）。

// tunNodePinIP TUN 下 SS/SOCKS 出站要钉的地址：双栈选中 IPv6 时钉 IPv6，否则钉首个 IPv4。

func (a *App) tunNodePinIP(host string) net.IP {
	if v, ok := a.tunPinV6[strings.ToLower(host)]; ok && v != nil {
		return v
	}
	if ips := lookupNodeIPv4sCached(host); len(ips) > 0 {
		return ips[0]
	}
	return nil
}

// tunNodeTargets 预校验并解析节点：IPv4 /32 出口 + 双栈时选中的 IPv6。

// 结果同时登记钉 IP 的选择（出站在内核启动 / 热切换时按它生成）。

func (a *App) tunNodeTargets(node NodeItem, tunIdx uint32) ([]hopRoute, *tunNodeV6, error) {
	v6 := pickTunNodeV6(node.Address, tunIdx)
	hops, err := tunNodeHops(node, tunIdx)
	if err != nil && v6 == nil {
		return nil, nil, err
	}
	if a.tunPinV6 == nil {
		a.tunPinV6 = map[string]net.IP{}
	}
	key := strings.ToLower(node.Address)
	if v6 != nil {
		a.tunPinV6[key] = v6.IP
	} else {
		delete(a.tunPinV6, key)
	}
	return hops, v6, nil
}

func describeNodeFamily(v6 *tunNodeV6) string {
	if v6 == nil {
		return "IPv4"
	}
	return "IPv6 " + v6.IP.String()
}
