// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv6

import (
	"testing"

	"golang.org/x/net/internal/iana"
	"golang.org/x/net/internal/socket"
)

func TestControlMessageParseUnsupported(t *testing.T) {
	// Model the empty Windows option table using the host's header layout.
	// Do not run in parallel with tests that use ctlOpts.
	saved := ctlOpts
	ctlOpts = [ctlMax]ctlOpt{}
	defer func() { ctlOpts = saved }()

	for _, tt := range []struct {
		name string
		typ  int
	}{
		{"packetinfo", 19}, // Windows IPV6_PKTINFO
		{"zero", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if socket.ControlMessageSpace(20) == 0 {
				t.Skip("control message headers not supported")
			}
			m := socket.NewControlMessage([]int{20})
			if _, err := m.Marshal(iana.ProtocolIPv6, tt.typ, make([]byte, 20)); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("Parse panicked: %v", v)
				}
			}()
			var cm ControlMessage
			if err := cm.Parse(m); err != errNotImplemented {
				t.Errorf("Parse = %v; want %v", err, errNotImplemented)
			}
		})
	}
	for _, b := range [][]byte{nil, {}, {1}} {
		var cm ControlMessage
		if err := cm.Parse(b); err != errNotImplemented {
			t.Errorf("Parse(%v) = %v; want %v", b, err, errNotImplemented)
		}
	}
}
