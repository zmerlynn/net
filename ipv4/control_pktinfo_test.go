// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || linux || solaris || windows

package ipv4

import (
	"net"
	"testing"

	"golang.org/x/net/internal/iana"
	"golang.org/x/net/internal/socket"
)

func TestPacketInfoParse(t *testing.T) {
	opt := ctlOpts[ctlPacketInfo]
	for n := 0; n < opt.length; n++ {
		m := socket.NewControlMessage([]int{n})
		if _, err := m.Marshal(iana.ProtocolIP, opt.name, make([]byte, n)); err != nil {
			t.Fatal(err)
		}
		var cm ControlMessage
		if err := cm.Parse(m); err == nil {
			t.Errorf("accepted packet info with %d payload bytes", n)
		}
	}
	// Use the native encoder for the packet info and independent unknown records
	// on either side. Unknown levels and types (including type zero) are skipped.
	info := (&ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 7}).Marshal()
	unknown := socket.NewControlMessage([]int{1, 1})
	next, err := unknown.Marshal(iana.ProtocolIP, 0, []byte{42})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.Marshal(999, opt.name, []byte{42}); err != nil {
		t.Fatal(err)
	}
	b := append(append(append([]byte{}, unknown...), info...), unknown...)
	var cm ControlMessage
	if err := cm.Parse(b); err != nil || cm.IfIndex != 7 {
		t.Fatalf("unknown records: cm=%v err=%v", &cm, err)
	}
	if err := cm.Parse(append(info, info...)); err == nil {
		t.Error("accepted duplicate packet info")
	}
}

func FuzzPacketInfoParse(f *testing.F) {
	f.Add([]byte{})
	f.Add((&ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 1}).Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		var cm ControlMessage
		if err := cm.Parse(b); err == nil && cm.Dst != nil && cm.Dst.To4() == nil {
			t.Fatalf("invalid destination %v", cm.Dst)
		}
	})
}
