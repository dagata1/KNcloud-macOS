//go:build windows

package main

// tunnode6_windows.go —— 双栈 TUN 的 Windows 部分：IPv6 路由表读取与节点 /128（netsh）。

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func listRoutes6() ([]mibIPForwardRow2, error) {
	var tbl uintptr
	r, _, _ := procGetIpForwardTable2.Call(windows.AF_INET6, uintptr(unsafe.Pointer(&tbl)))
	if r != 0 {
		return nil, windows.Errno(r)
	}
	defer procFreeMibTable.Call(tbl)
	n := *(*uint32)(unsafe.Pointer(tbl))
	const rowSize = unsafe.Sizeof(mibIPForwardRow2{})
	base := tbl + 8
	rows := make([]mibIPForwardRow2, n)
	for i := uint32(0); i < n; i++ {
		rows[i] = *(*mibIPForwardRow2)(unsafe.Pointer(base + uintptr(i)*rowSize))
	}
	return rows, nil
}

func sockaddrIn6Addr(b []byte) net.IP {
	if len(b) < 24 || *(*uint16)(unsafe.Pointer(&b[0])) != windows.AF_INET6 {
		return nil
	}
	ip := make(net.IP, 16)
	copy(ip, b[8:24])
	return ip
}

func physV6Exit(tunIdx uint32) (ifIdx uint32, nextHop net.IP, ok bool) {
	rows, err := listRoutes6()
	if err != nil {
		return 0, nil, false
	}
	nativeIdx := nativeTunIdxCached()
	best := ^uint32(0)
	for _, row := range rows {
		if row.DestinationPrefix[28] != 0 || row.InterfaceIndex == 0 ||
			row.InterfaceIndex == tunIdx || (nativeIdx != 0 && row.InterfaceIndex == nativeIdx) {
			continue
		}
		if row.Metric >= best || !ifaceHasGlobalV6(row.InterfaceIndex) {
			continue
		}
		hop := sockaddrIn6Addr(row.NextHop[:])
		if hop != nil && hop.IsUnspecified() {
			hop = nil
		}
		best, ifIdx, nextHop, ok = row.Metric, row.InterfaceIndex, hop, true
	}
	return ifIdx, nextHop, ok
}

func (v *tunNodeV6) netshArgs(op string) []string {
	args := []string{"interface", "ipv6", op, "route", "prefix=" + v.IP.String() + "/128",
		fmt.Sprintf("interface=%d", v.IfIndex)}
	if op == "add" {
		if v.NextHop != nil {
			args = append(args, "nexthop="+v.NextHop.String())
		}
		args = append(args, fmt.Sprintf("metric=%d", hostRouteMetric), "store=active", "publish=no")
	} else {
		if v.NextHop != nil {
			args = append(args, "nexthop="+v.NextHop.String())
		}
		args = append(args, "store=active")
	}
	return args
}

func hasNodeV6Route(v *tunNodeV6) bool {
	rows, err := listRoutes6()
	if err != nil {
		return false
	}
	for _, row := range rows {
		if row.DestinationPrefix[28] == 128 && row.InterfaceIndex == v.IfIndex &&
			v.IP.Equal(sockaddrIn6Addr(row.DestinationPrefix[:28])) {
			return true
		}
	}
	return false
}

func addNodeV6Route(v *tunNodeV6) error {
	if v == nil {
		return nil
	}
	if hasNodeV6Route(v) {
		return nil
	}
	out, err := runHidden("netsh", v.netshArgs("add")...)
	if err != nil {
		return fmt.Errorf("add IPv6 node route %s/128: %v: %s", v.IP, err, strings.TrimSpace(string(out)))
	}
	if !hasNodeV6Route(v) {
		return fmt.Errorf("netsh did not create %s/128 on ifIdx=%d: %s", v.IP, v.IfIndex, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeNodeV6Route(v *tunNodeV6) {
	if v == nil {
		return
	}
	_, _ = runHidden("netsh", v.netshArgs("delete")...)
}
