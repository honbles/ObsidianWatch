package otel

import (
	"encoding/binary"
	"net"
	"testing"
)

func row4(local net.IP, lp uint16, remote net.IP, rp uint16, pid uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], 5) // established
	copy(b[4:8], local.To4())
	b[8], b[9] = byte(lp>>8), byte(lp)
	copy(b[12:16], remote.To4())
	b[16], b[17] = byte(rp>>8), byte(rp)
	binary.LittleEndian.PutUint32(b[20:], pid)
	return b
}

func TestOwnerOfClient4(t *testing.T) {
	lo := net.ParseIP("127.0.0.1")
	tbl := make([]byte, 4)
	binary.LittleEndian.PutUint32(tbl, 3)
	tbl = append(tbl, row4(lo, 4318, lo, 55000, 111)...)  // server end (must be ignored)
	tbl = append(tbl, row4(lo, 55000, lo, 4318, 4242)...) // client end
	tbl = append(tbl, row4(lo, 55001, lo, 4318, 999)...)
	if rows := ParseTCP4(tbl); rows[0].State != "ESTABLISHED" {
		t.Fatalf("state = %q", rows[0].State)
	}
	got := OwnerOfClient(ParseTCP4(tbl), &net.TCPAddr{IP: lo, Port: 55000}, &net.TCPAddr{IP: lo, Port: 4318})
	if got != 4242 {
		t.Fatalf("owner = %d, want 4242", got)
	}
	if OwnerOfClient(ParseTCP4(tbl), &net.TCPAddr{IP: lo, Port: 1}, &net.TCPAddr{IP: lo, Port: 4318}) != 0 {
		t.Fatal("unknown connection must not resolve")
	}
}

func TestOwnerOfClient6(t *testing.T) {
	b := make([]byte, 56)
	copy(b[0:16], net.IPv6loopback)
	b[20], b[21] = 0xD6, 0xD8 // 55000
	copy(b[24:40], net.IPv6loopback)
	b[40], b[41] = 0x10, 0xDE // 4318
	binary.LittleEndian.PutUint32(b[52:], 777)
	tbl := append([]byte{1, 0, 0, 0}, b...)
	got := OwnerOfClient(ParseTCP6(tbl), &net.TCPAddr{IP: net.IPv6loopback, Port: 55000}, &net.TCPAddr{IP: net.IPv6loopback, Port: 4318})
	if got != 777 {
		t.Fatalf("owner = %d, want 777", got)
	}
}

func TestParseTruncated(t *testing.T) {
	if len(ParseTCP4([]byte{9, 0, 0, 0, 1, 2})) != 0 || len(ParseTCP6(nil)) != 0 {
		t.Fatal("truncated tables must parse to nothing")
	}
}
