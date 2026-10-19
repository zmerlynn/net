// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv4

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/internal/socket"
)

func windowsUDP(t *testing.T) (*net.UDPConn, *PacketConn, int) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil && ip.Equal(net.IPv4(127, 0, 0, 1)) {
				index = iface.Index
			}
		}
	}
	if index == 0 {
		t.Fatal("127.0.0.1 has no interface")
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	p := NewPacketConn(c)
	if err := p.SetControlMessage(FlagDst|FlagInterface, true); err != nil {
		t.Fatal(err)
	}
	if err := p.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c, p, index
}

func TestWindowsUDPControlMessage(t *testing.T) {
	c, p, index := windowsUDP(t)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.LocalAddr().(*net.UDPAddr).Port}
	// Separately changing one flag must leave the shared socket option enabled.
	for _, flags := range []ControlFlags{0, FlagDst, FlagInterface} {
		if flags != 0 {
			if err := p.SetControlMessage(flags, false); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 32)
		n, cm, from, err := p.ReadFrom(b)
		if err != nil || string(b[:n]) != "scan" || cm == nil || !cm.Dst.Equal(dst.IP) || cm.IfIndex != index || cm.Src != nil {
			t.Fatalf("read: n=%d cm=%v from=%v err=%v; want dst=%v index=%d", n, cm, from, err, dst.IP, index)
		}
		for _, tt := range []struct {
			name    string
			control *ControlMessage
			wantErr string
		}{
			{name: "source_and_index", control: &ControlMessage{Src: dst.IP, IfIndex: index}},
			{name: "source", control: &ControlMessage{Src: dst.IP}},
			{name: "index", control: &ControlMessage{IfIndex: index}, wantErr: "source address required with interface index on Windows"},
			{name: "zero_source_and_index", control: &ControlMessage{Src: net.IPv4zero, IfIndex: index}, wantErr: "source address required with interface index on Windows"},
			{name: "nil"},
		} {
			t.Run(fmt.Sprintf("disabled_flags_%d/%s", flags, tt.name), func(t *testing.T) {
				n, err := p.WriteTo([]byte("reply"), tt.control, from)
				if tt.wantErr != "" {
					if n != 0 || err == nil || err.Error() != tt.wantErr {
						t.Fatalf("write control %v: n=%d err=%v; want n=0 err=%q", tt.control, n, err, tt.wantErr)
					}
					return
				}
				if err != nil || n != len("reply") {
					t.Fatalf("write control %v: n=%d err=%v; want n=5 err=nil", tt.control, n, err)
				}
				n, source, err := peer.ReadFromUDP(b)
				if err != nil || string(b[:n]) != "reply" || !source.IP.Equal(dst.IP) || source.Port != dst.Port {
					t.Fatalf("reply control %v: n=%d from=%v err=%v; want %v", tt.control, n, source, err, dst)
				}
			})
		}
		if flags != 0 {
			if err := p.SetControlMessage(flags, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := p.SetControlMessage(FlagDst|FlagInterface, false); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
		t.Fatal(err)
	}
	if _, cm, _, err := p.ReadFrom(make([]byte, 32)); err != nil || cm != nil {
		t.Fatalf("disabled controls: cm=%v err=%v", cm, err)
	}
}

// Observe the standard library directly so verbose CI logs show when its
// synchronous WSASendMsg byte count is fixed. Delivery must work either way.
func TestWindowsUDPWriteMsgCount(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := c.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	payload := []byte("reply")
	n, _, err := c.WriteMsgUDP(payload, nil, peer.LocalAddr().(*net.UDPAddr))
	t.Logf("net.UDPConn.WriteMsgUDP with nil OOB: n=%d err=%v payload length=%d", n, err, len(payload))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	n, _, err = peer.ReadFromUDP(b)
	if err != nil || string(b[:n]) != string(payload) {
		t.Fatalf("read: n=%d payload=%q err=%v; want %q", n, b[:n], err, payload)
	}
}

func TestWindowsUDPWriteDeadline(t *testing.T) {
	c, p, _ := windowsUDP(t)
	if err := p.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.LocalAddr().(*net.UDPAddr).Port}
	n, err := p.WriteTo([]byte("reply"), nil, dst)
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() || n != 0 {
		t.Fatalf("write deadline: n=%d err=%v; want n=0 and timeout", n, err)
	}
}

func TestWindowsUDPDeadlineAndClose(t *testing.T) {
	_, p, _ := windowsUDP(t)
	p.SetReadDeadline(time.Now())
	if _, cm, _, err := p.ReadFrom(make([]byte, 32)); err == nil {
		t.Fatal("expired deadline succeeded")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() || cm != nil {
		t.Fatalf("deadline: cm=%v err=%v", cm, err)
	}
	p.SetReadDeadline(time.Time{})
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { close(started); _, _, _, err := p.ReadFrom(make([]byte, 32)); done <- err }()
	<-started
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
}

func TestWindowsUDPTinyBuffers(t *testing.T) {
	c, p, _ := windowsUDP(t)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP(make([]byte, 32), dst); err != nil {
		t.Fatal(err)
	}
	if n, cm, from, err := p.ReadFrom(make([]byte, 1)); n != 0 || cm != nil || from != nil || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("tiny payload: n=%d cm=%v from=%v err=%v", n, cm, from, err)
	}
	// Exercise the actual stdlib transport with insufficient ancillary space,
	// then feed its flags/error into the same validation used by ReadFrom.
	if _, err := peer.WriteToUDP([]byte("scan"), dst); err != nil {
		t.Fatal(err)
	}
	oob := make([]byte, 1)
	_, nn, flags, _, err := c.ReadMsgUDP(make([]byte, 32), oob)
	if cm, err := parseControlMessage(oob, nn, flags, err); cm != nil || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("tiny controls: cm=%v err=%v", cm, err)
	}
	// Failed reads consume only that datagram; the socket remains usable.
	if _, err := peer.WriteToUDP([]byte("ok"), dst); err != nil {
		t.Fatal(err)
	}
	if n, cm, _, err := p.ReadFrom(make([]byte, 32)); err != nil || n != 2 || cm == nil {
		t.Fatalf("recovery: n=%d cm=%v err=%v", n, cm, err)
	}
}

func TestWindowsUnsupportedControls(t *testing.T) {
	_, p, _ := windowsUDP(t)
	for _, flags := range []ControlFlags{FlagTTL, FlagSrc, FlagTTL | FlagDst, 1 << 20} {
		for _, on := range []bool{false, true} {
			if err := p.SetControlMessage(flags, on); !errors.Is(err, errNotImplemented) {
				t.Errorf("flags=%v on=%v: %v", flags, on, err)
			}
		}
	}
	ms := []Message{{Buffers: [][]byte{make([]byte, 1)}}}
	if _, err := p.ReadBatch(ms, 0); !errors.Is(err, errNotImplemented) {
		t.Errorf("ReadBatch: %v", err)
	}
	if _, err := p.WriteBatch(ms, 0); !errors.Is(err, errNotImplemented) {
		t.Errorf("WriteBatch: %v", err)
	}
	if _, err := p.WriteTo([]byte("x"), &ControlMessage{TTL: 1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}); !errors.Is(err, errNotImplemented) {
		t.Errorf("write TTL: %v", err)
	}
	// An IPConn often needs administrator privileges. The type dispatch can be
	// checked without opening a raw socket or making a syscall.
	cc := new(socket.Conn)
	ip := &PacketConn{dgramOpt: dgramOpt{Conn: cc}, payloadHandler: payloadHandler{PacketConn: new(net.IPConn), Conn: cc}}
	if err := ip.SetControlMessage(FlagDst|FlagInterface, true); !errors.Is(err, errNotImplemented) {
		t.Errorf("IPConn controls: %v", err)
	}
	if _, _, _, err := ip.ReadFrom(nil); !errors.Is(err, errNotImplemented) {
		t.Errorf("IPConn read: %v", err)
	}
	if _, err := ip.WriteTo(nil, nil, nil); !errors.Is(err, errNotImplemented) {
		t.Errorf("IPConn write: %v", err)
	}
	raw := &RawConn{dgramOpt: dgramOpt{Conn: cc}, packetHandler: packetHandler{IPConn: new(net.IPConn), Conn: cc}}
	if err := raw.SetControlMessage(FlagDst|FlagInterface, true); !errors.Is(err, errNotImplemented) {
		t.Errorf("RawConn controls: %v", err)
	}
}
