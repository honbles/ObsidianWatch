//go:build windows

package otel

// peer_windows.go - peer identification on Windows. A loopback TCP connection is mapped to the
// owning process with GetExtendedTcpTable (TCP_TABLE_OWNER_PID_ALL): the table row whose local
// end is the sender's address owns the client socket. Image path, start time and parent come
// from the process handle and a Toolhelp snapshot. Windows has no container id to report.

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	afInet              = 2
	afInet6             = 23
)

type windowsResolver struct{}

// NewPeerResolver returns the Windows resolver.
func NewPeerResolver() PeerResolver { return windowsResolver{} }

func extendedTCPTable(family uint32) ([]byte, error) {
	size := uint32(32 * 1024)
	for try := 0; try < 6; try++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDAll, 0)
		switch r {
		case 0:
			return buf[:size], nil
		case uintptr(syscall.ERROR_INSUFFICIENT_BUFFER):
			size += 16 * 1024 // the table grew between calls; retry with the size it reported
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: error %d", r)
		}
	}
	return nil, fmt.Errorf("GetExtendedTcpTable: table kept growing")
}

func (windowsResolver) Resolve(c net.Conn) Peer {
	conn, ok := c.(*net.TCPConn)
	if !ok {
		return Peer{Reason: "unsupported connection type"}
	}
	ra, ok1 := conn.RemoteAddr().(*net.TCPAddr)
	la, ok2 := conn.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return Peer{Reason: "not a TCP address"}
	}
	family, parse := uint32(afInet), ParseTCP4
	if ra.IP.To4() == nil {
		family, parse = afInet6, ParseTCP6
	}
	buf, err := extendedTCPTable(family)
	if err != nil {
		return Peer{Reason: err.Error()}
	}
	pid := OwnerOfClient(parse(buf), ra, la)
	if pid == 0 {
		return Peer{Reason: "no process owns the client socket"}
	}
	return describeWindowsProcess(pid)
}

func describeWindowsProcess(pid uint32) Peer {
	p := Peer{Resolved: true, PID: int(pid)}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Peer{Reason: "process exited or cannot be opened"}
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		p.Exe = windows.UTF16ToString(buf[:n])
	}
	var creation, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &creation, &exit, &kernel, &user) == nil {
		p.ProcStart = time.Unix(0, creation.Nanoseconds()).UTC().Truncate(time.Millisecond)
	}
	p.PPID = parentPID(pid)
	return p
}

func parentPID(pid uint32) int {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ProcessID == pid {
			return int(pe.ParentProcessID)
		}
	}
	return 0
}

// TCPTable returns the IPv4 and IPv6 TCP tables with their owning processes (used by the host sensor).
func TCPTable() ([]TCPRow, error) {
	var out []TCPRow
	var firstErr error
	for _, f := range []struct {
		family uint32
		parse  func([]byte) []TCPRow
	}{{afInet, ParseTCP4}, {afInet6, ParseTCP6}} {
		buf, err := extendedTCPTable(f.family)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, f.parse(buf)...)
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}
