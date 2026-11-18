package otel

// tcptable.go - parsing of the Windows extended TCP tables (GetExtendedTcpTable with
// TCP_TABLE_OWNER_PID_ALL). Pure byte parsing with no Windows calls, so it is unit-tested on any OS.

import (
	"encoding/binary"
	"net"
)

// TCPRow is one connection and the process that owns its local end.
type TCPRow struct {
	State                 string // LISTEN, ESTABLISHED, SYN_SENT, ...
	LocalIP, RemoteIP     net.IP
	LocalPort, RemotePort uint16
	PID                   uint32
}

// ports in these tables are 32-bit fields holding a network-order 16-bit value in the low bytes.
func tablePort(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// ParseTCP4 parses MIB_TCPTABLE_OWNER_PID: DWORD count, then rows of
// {state, localAddr, localPort, remoteAddr, remotePort, owningPid} (6 DWORDs).
func ParseTCP4(buf []byte) []TCPRow {
	if len(buf) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(buf))
	var out []TCPRow
	for i := 0; i < n; i++ {
		o := 4 + i*24
		if o+24 > len(buf) {
			break
		}
		r := buf[o : o+24]
		out = append(out, TCPRow{
			State:   tcpState(binary.LittleEndian.Uint32(r[0:4])),
			LocalIP: net.IPv4(r[4], r[5], r[6], r[7]), LocalPort: tablePort(r[8:12]),
			RemoteIP: net.IPv4(r[12], r[13], r[14], r[15]), RemotePort: tablePort(r[16:20]),
			PID: binary.LittleEndian.Uint32(r[20:24]),
		})
	}
	return out
}

// ParseTCP6 parses MIB_TCP6TABLE_OWNER_PID: DWORD count, then rows of
// {localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, owningPid} (56 bytes).
func ParseTCP6(buf []byte) []TCPRow {
	if len(buf) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(buf))
	var out []TCPRow
	for i := 0; i < n; i++ {
		o := 4 + i*56
		if o+56 > len(buf) {
			break
		}
		r := buf[o : o+56]
		l := make(net.IP, 16)
		rm := make(net.IP, 16)
		copy(l, r[0:16])
		copy(rm, r[24:40])
		out = append(out, TCPRow{
			State:   tcpState(binary.LittleEndian.Uint32(r[48:52])),
			LocalIP: l, LocalPort: tablePort(r[20:24]),
			RemoteIP: rm, RemotePort: tablePort(r[40:44]),
			PID: binary.LittleEndian.Uint32(r[52:56]),
		})
	}
	return out
}

// OwnerOfClient finds the process owning the CLIENT end of the connection: the row whose local
// address is the peer's address and whose remote address is the receiver's.
func OwnerOfClient(rows []TCPRow, client, server *net.TCPAddr) uint32 {
	for _, r := range rows {
		if int(r.LocalPort) == client.Port && int(r.RemotePort) == server.Port &&
			r.LocalIP.Equal(client.IP) && r.RemoteIP.Equal(server.IP) {
			return r.PID
		}
	}
	return 0
}

// tcpState names a MIB_TCP_STATE value.
func tcpState(v uint32) string {
	switch v {
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RCVD"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT1"
	case 7:
		return "FIN_WAIT2"
	case 8:
		return "CLOSE_WAIT"
	case 11:
		return "TIME_WAIT"
	}
	return "OTHER"
}
