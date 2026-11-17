package main

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// devicePingBindControl 把上报 socket 绑定到物理网卡（TUN 接管时用）：
// IPv4 用 IP_UNICAST_IF（网络字节序的接口索引），IPv6 用 IPV6_UNICAST_IF（主机字节序）。
// 与内核出站 sockopt.interface 的做法一致，默认路由在 TUN 上也会从物理网卡出去。
func devicePingBindControl(ifIdx uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if len(network) > 0 && network[len(network)-1] == '6' {
				serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, 31 /*IPV6_UNICAST_IF*/, int(ifIdx))
				return
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], ifIdx)
			v := *(*int32)(unsafe.Pointer(&b[0]))
			serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 31 /*IP_UNICAST_IF*/, int(v))
		})
		if err != nil {
			return err
		}
		return serr
	}
}
