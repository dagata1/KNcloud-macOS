//go:build darwin

package main

import (
	"net"
	"testing"
)

func TestValidateHelperRouteV6ZonedGateway(t *testing.T) {
	r, err := validateHelperRoute(helperReq{Op: "route_add", Dst: "2001:db8::1/128", Gateway: "fe80::1%en0", V6: true})
	if err != nil {
		t.Fatalf("zoned link-local gateway rejected: %v", err)
	}
	args := routeCmdArgs("add", r)
	if got := args[len(args)-1]; got != "fe80::1%en0" {
		t.Fatalf("gateway arg = %q, want fe80::1%%en0 (args %v)", got, args)
	}
	for _, bad := range []string{"fe80::1%en0;rm", "fe80::1%", "nope%en0"} {
		if _, err := validateHelperRoute(helperReq{Op: "route_add", Dst: "2001:db8::1/128", Gateway: bad, V6: true}); err == nil {
			t.Errorf("gateway %q should be rejected", bad)
		}
	}
}

func TestNodeV6HelperReq(t *testing.T) {
	ifc, err := net.InterfaceByIndex(1)
	if err != nil {
		t.Skip("no interface 1")
	}
	v := &tunNodeV6{IP: net.ParseIP("2001:db8::5"), IfIndex: uint32(ifc.Index), NextHop: net.ParseIP("fe80::1")}
	req, err := v.helperReq("route_add")
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst != "2001:db8::5/128" || !req.V6 || req.Gateway != "fe80::1%"+ifc.Name {
		t.Fatalf("unexpected req %+v", req)
	}
}
