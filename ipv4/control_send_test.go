// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv4

import (
	"net"
	"testing"
)

// Windows send validation does not need a socket or the Windows ABI.
func TestControlMessageValidateWindows(t *testing.T) {
	for _, tt := range []struct {
		name string
		cm   *ControlMessage
		want string
	}{
		{name: "nil"},
		{name: "empty", cm: &ControlMessage{}},
		{name: "source", cm: &ControlMessage{Src: net.IPv4(127, 0, 0, 1)}},
		{name: "source_and_index", cm: &ControlMessage{Src: net.IP{127, 0, 0, 1}, IfIndex: 1}},
		{name: "mapped_source_and_index", cm: &ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 1}},
		{name: "index", cm: &ControlMessage{IfIndex: 1}, want: "source address required with interface index on Windows"},
		{name: "empty_source_and_index", cm: &ControlMessage{Src: net.IP{}, IfIndex: 1}, want: "source address required with interface index on Windows"},
		{name: "zero_source_and_index", cm: &ControlMessage{Src: net.IP{0, 0, 0, 0}, IfIndex: 1}, want: "source address required with interface index on Windows"},
		{name: "mapped_zero_source_and_index", cm: &ControlMessage{Src: net.IPv4zero, IfIndex: 1}, want: "source address required with interface index on Windows"},
		{name: "ipv6_source_and_index", cm: &ControlMessage{Src: net.IPv6loopback, IfIndex: 1}, want: "invalid control message"},
		{name: "negative_index", cm: &ControlMessage{IfIndex: -1}, want: "invalid control message"},
		{name: "ttl", cm: &ControlMessage{TTL: 1}, want: errNotImplemented.Error()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cm.validateWindows()
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Fatalf("control %v: error = %q; want %q", tt.cm, got, tt.want)
			}
		})
	}
}
