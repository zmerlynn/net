// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socket

import (
	"bytes"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Negative array bounds make these ABI assertions compile checks as well as
// runtime tests, including when cross-compiling windows/386.
const (
	pointerSize = unsafe.Sizeof(uintptr(0))
	headerSize  = unsafe.Sizeof(windows.WSACMSGHDR{})
	levelOffset = unsafe.Offsetof(windows.WSACMSGHDR{}.Level)
	typeOffset  = unsafe.Offsetof(windows.WSACMSGHDR{}.Type)
)

var (
	_ [headerSize - (pointerSize + 8)]byte
	_ [(pointerSize + 8) - headerSize]byte
	_ [levelOffset - pointerSize]byte
	_ [pointerSize - levelOffset]byte
	_ [typeOffset - (pointerSize + 4)]byte
	_ [(pointerSize + 4) - typeOffset]byte
)

func TestWindowsControlHeader(t *testing.T) {
	if unsafe.Offsetof(windows.WSACMSGHDR{}.Len) != 0 || controlHeaderLen() != int(headerSize) {
		t.Fatal("unexpected WSACMSGHDR layout")
	}
	// Literal little-endian fixtures: SIZE_T length, int32 level/type, payload.
	want := []byte{20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 127, 0, 0, 1}
	if pointerSize == 4 {
		want = []byte{16, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 127, 0, 0, 1}
	}
	m := NewControlMessage([]int{4})
	if _, err := m.Marshal(0, 19, []byte{127, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m[:len(want)], want) {
		t.Fatalf("got %x; want %x", m, want)
	}
	t.Logf("WSACMSGHDR: size=%d Len=0 Level=%d Type=%d alignment=%d", headerSize, levelOffset, typeOffset, pointerSize)
}
