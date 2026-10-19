// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows || zos

package socket

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestControlMessageLengths(t *testing.T) {
	for _, size := range []int{controlHeaderLen(), ControlMessageSpace(8)} {
		for _, n := range []int{0, 1, controlHeaderLen() - 1, size + 1, -1, int(^uint(0) >> 1)} {
			m := make(ControlMessage, size)
			(*cmsghdr)(unsafe.Pointer(&m[0])).set(n, 0, 19)
			if _, err := m.Parse(); err == nil {
				t.Errorf("Parse with record length %d and buffer length %d succeeded", n, size)
			}
		}
	}
	// Trailing bytes too short for a header are ignored.
	for n := 1; n < controlHeaderLen(); n++ {
		if ms, err := ControlMessage(make([]byte, n)).Parse(); err != nil || len(ms) != 0 {
			t.Errorf("Parse with %d header bytes: messages=%v err=%v", n, ms, err)
		}
	}
	m := NewControlMessage([]int{1})
	if err := m.MarshalHeader(0, 19, 1); err != nil {
		t.Fatal(err)
	}
	m.Data(1)[0] = 42
	// All final padding lengths, including omitted and nonzero padding, are valid.
	for n := controlHeaderLen() + 1; n <= len(m); n++ {
		b := bytes.Clone(m[:n])
		for i := controlHeaderLen() + 1; i < n; i++ {
			b[i] = 0xff
		}
		ms, err := ControlMessage(b).Parse()
		if err != nil || len(ms) != 1 || !bytes.Equal(ms[0].Data(1), []byte{42}) {
			t.Errorf("padding length %d: messages=%v err=%v", n, ms, err)
		}
	}
	if ms, err := ControlMessage(append(m, 1)).Parse(); err != nil || len(ms) != 1 {
		t.Errorf("trailing byte: messages=%v err=%v", ms, err)
	}
	if _, err := ControlMessage(nil).Parse(); err != nil {
		t.Fatal(err)
	}
	if m.Data(-1) != nil || m.Data(int(^uint(0)>>1)) != nil {
		t.Error("invalid data length accepted")
	}
	for _, n := range []int{-1, int(^uint(0) >> 1)} {
		if err := m.MarshalHeader(0, 19, n); err == nil {
			t.Errorf("MarshalHeader with payload length %d succeeded", n)
		}
	}
	// ParseHeader validates the record length itself, not only via Parse.
	for _, n := range []int{0, controlHeaderLen() - 1, len(m) + 1} {
		b := ControlMessage(bytes.Clone(m))
		(*cmsghdr)(unsafe.Pointer(&b[0])).set(n, 0, 19)
		if _, _, _, err := b.ParseHeader(); err == nil {
			t.Errorf("ParseHeader with record length %d and buffer length %d succeeded", n, len(b))
		}
	}
}

func FuzzControlMessageParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1})
	m := NewControlMessage([]int{8, 1})
	next, err := m.Marshal(0, 19, []byte{127, 0, 0, 1, 1, 0, 0, 0})
	if err != nil {
		f.Fatal(err)
	}
	if _, err := next.Marshal(999, 999, []byte{42}); err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(m))
	f.Fuzz(func(t *testing.T, b []byte) {
		ms, err := ControlMessage(b).Parse()
		if err != nil {
			return
		}
		for _, m := range ms {
			_, _, n, err := m.ParseHeader()
			if err != nil || n < 0 || n > len(m)-controlHeaderLen() || len(m.Data(n)) != n {
				t.Fatalf("invalid parsed message %x: length=%d err=%v", m, n, err)
			}
		}
	})
}
