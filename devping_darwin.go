//go:build darwin

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// devicePingBindControl 把上报 socket 绑定到物理网卡（TUN 接管时用）：IP_BOUND_IF /
// IPV6_BOUND_IF，与内核出站 sockopt.interface 的做法一致。IPv4 依赖 TUN 开启时装上的
// 物理网卡作用域默认路由（见 scopedPhysDefaultReq）；IPv6 依赖系统为该网卡装的作用域
// 默认路由（路由器通告时系统会装），没有时连接失败，上报静默跳过。
func devicePingBindControl(ifIdx uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if len(network) > 0 && network[len(network)-1] == '6' {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(ifIdx))
				return
			}
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(ifIdx))
		})
		if err != nil {
			return err
		}
		return serr
	}
}
