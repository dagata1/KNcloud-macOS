//go:build darwin

package main

// tunnode6_darwin.go —— 双栈 TUN 的 macOS 部分：从内核 IPv6 路由表找物理出口，
// 节点 /128 经特权助手写入（route add -inet6 <ip>/128 <gw%en0>）。

import (
	"fmt"
	"net"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// physV6Exit 本机的物理 IPv6 出口：一条不在 utun/回环上的 ::/0 默认路由，且该网卡有全球单播
// IPv6 地址。同等条件下优先非 IFSCOPE 的主路由。没有就说明本机没有 IPv6 出口。TUN 运行中也能正确返回。
func physV6Exit(tunIdx uint32) (ifIdx uint32, nextHop net.IP, ok bool) {
	rib, err := route.FetchRIB(unix.AF_INET6, route.RIBTypeRoute, 0)
	if err != nil {
		return 0, nil, false
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return 0, nil, false
	}
	exclude := tunIdx
	if exclude == 0 {
		exclude = darwinTunIfIdx.Load()
	}
	bestScoped := true
	for _, m := range msgs {
		rm, okm := m.(*route.RouteMessage)
		if !okm || rm.Flags&unix.RTF_UP == 0 || rm.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE|unix.RTF_HOST) != 0 {
			continue
		}
		if len(rm.Addrs) <= unix.RTAX_NETMASK || rm.Index == 0 {
			continue
		}
		idx := uint32(rm.Index)
		if idx == exclude || idx == darwinTunIfIdx.Load() || isLoopbackIfIndex(idx) {
			continue
		}
		dst, okd := rm.Addrs[unix.RTAX_DST].(*route.Inet6Addr)
		if !okd || !net.IP(dst.IP[:]).IsUnspecified() {
			continue
		}
		// 默认路由：掩码缺省或全零
		if mask, okk := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet6Addr); okk && !net.IP(mask.IP[:]).IsUnspecified() {
			continue
		}
		if !ifaceHasGlobalV6(idx) {
			continue
		}
		scoped := rm.Flags&unix.RTF_IFSCOPE != 0
		if ok && (scoped || !bestScoped) {
			continue // 已有候选：只用非作用域主路由替换作用域路由
		}
		var hop net.IP
		if gw, okg := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet6Addr); okg && rm.Flags&unix.RTF_GATEWAY != 0 {
			hop = make(net.IP, 16)
			copy(hop, gw.IP[:])
		}
		ifIdx, nextHop, ok, bestScoped = idx, hop, true, scoped
	}
	return ifIdx, nextHop, ok
}

// helperReq 形式的节点 /128：有网关时写 gw%ifname（链路本地网关必须带接口），否则按接口 on-link。
func (v *tunNodeV6) helperReq(op string) (helperReq, error) {
	name := ifaceNameByIndex(v.IfIndex)
	if name == "" {
		return helperReq{}, fmt.Errorf("interface index %d not found", v.IfIndex)
	}
	req := helperReq{Op: op, Dst: v.IP.String() + "/128", V6: true}
	if v.NextHop != nil {
		gw := v.NextHop.String()
		if v.NextHop.IsLinkLocalUnicast() {
			gw += "%" + name
		}
		req.Gateway = gw
	} else {
		req.Iface = name
	}
	return req, nil
}

// addNodeV6Route 写节点 IPv6 /128 走物理网卡（已存在视为成功）。
func addNodeV6Route(v *tunNodeV6) error {
	if v == nil {
		return nil
	}
	req, err := v.helperReq("route_add")
	if err != nil {
		return err
	}
	if _, err := tunHelper.do(req); err != nil {
		return fmt.Errorf("add IPv6 node route %s/128: %v", v.IP, err)
	}
	return nil
}

// removeNodeV6Route 撤节点 IPv6 /128（助手只删自己加过的；不存在视为成功）。
func removeNodeV6Route(v *tunNodeV6) {
	if v == nil || !tunHelper.connected() {
		return
	}
	if req, err := v.helperReq("route_del"); err == nil {
		_, _ = tunHelper.do(req)
	}
}
