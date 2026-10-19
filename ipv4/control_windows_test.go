// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv4

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"unsafe"

	"golang.org/x/net/internal/socket"
	"golang.org/x/sys/windows"
)

const (
	pktinfoSize        = unsafe.Sizeof(windows.IN_PKTINFO{})
	pktinfoIndexOffset = unsafe.Offsetof(windows.IN_PKTINFO{}.Ifindex)
)

var (
	_ [pktinfoSize - 8]byte
	_ [8 - pktinfoSize]byte
	_ [pktinfoIndexOffset - 4]byte
	_ [4 - pktinfoIndexOffset]byte
)

func TestWindowsPacketInfo(t *testing.T) {
	if unsafe.Offsetof(windows.IN_PKTINFO{}.Addr) != 0 {
		t.Fatal("unexpected IN_PKTINFO layout")
	}
	t.Logf("IN_PKTINFO: size=%d Addr=0 Ifindex=%d", pktinfoSize, pktinfoIndexOffset)
	cm := &ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 7}
	b := cm.Marshal()
	// Independent literal pktinfo payload, including a little-endian ULONG index.
	want := []byte{127, 0, 0, 1, 7, 0, 0, 0}
	if got := socket.ControlMessage(b).Data(8); !bytes.Equal(got, want) {
		t.Fatalf("got %x; want %x", got, want)
	}
	var got ControlMessage
	if err := got.Parse(b); err != nil || !got.Dst.Equal(cm.Src) || got.IfIndex != cm.IfIndex || got.Src != nil {
		t.Fatalf("parse: %v err=%v", &got, err)
	}
}

func TestWindowsTruncatedControl(t *testing.T) {
	b := (&ControlMessage{Src: net.IPv4(127, 0, 0, 1), IfIndex: 7}).Marshal()
	for _, tc := range []struct {
		n, flags int
		err      error
	}{
		{len(b), windows.MSG_TRUNC, nil},
		{len(b), windows.MSG_CTRUNC, nil},
		{len(b) + 1, 0, nil},
		{-1, 0, nil},
		{len(b) + 1, 0, windows.WSAEMSGSIZE},
	} {
		cm, err := parseControlMessage(b, tc.n, tc.flags, tc.err)
		if cm != nil || !errors.Is(err, io.ErrShortBuffer) {
			t.Errorf("%+v: cm=%v err=%v", tc, cm, err)
		}
		if tc.err != nil && !errors.Is(err, tc.err) {
			t.Errorf("lost socket error: %v", err)
		}
	}
	for _, b := range [][]byte{nil, {}} {
		if cm, err := parseControlMessage(b, 0, 0, nil); cm != nil || err != nil {
			t.Errorf("empty control: %v %v", cm, err)
		}
	}
}
