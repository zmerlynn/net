// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv6

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsControlMessageParseUnsupported(t *testing.T) {
	for _, tt := range []struct {
		name string
		typ  int32
	}{
		{"packetinfo", windows.IPV6_PKTINFO},
		{"zero", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Use x/sys headers and payloads independently of the socket codec.
			headerLen := int(unsafe.Sizeof(windows.WSACMSGHDR{}))
			b := make([]byte, headerLen+int(unsafe.Sizeof(windows.IN6_PKTINFO{})))
			h := (*windows.WSACMSGHDR)(unsafe.Pointer(&b[0]))
			h.Len = uintptr(len(b))
			h.Level = windows.IPPROTO_IPV6
			h.Type = tt.typ
			pi := (*windows.IN6_PKTINFO)(unsafe.Pointer(&b[headerLen]))
			pi.Addr[15] = 1 // ::1
			pi.Ifindex = 7
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("Parse panicked: %v", v)
				}
			}()
			var cm ControlMessage
			if err := cm.Parse(b); err != errNotImplemented {
				t.Errorf("Parse = %v; want %v", err, errNotImplemented)
			}
		})
	}
}
