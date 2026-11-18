//go:build windows

package ebpf

// host_windows.go - process and TCP snapshots on Windows: Toolhelp for the process list, the
// process handle for image path / start time / command line / owner, and the extended TCP table
// (owner pid per socket). Per-process details never change, so they are read once per process.

import (
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"obsidianwatch/agent/internal/otel"
)

type winHost struct {
	cache map[int]procRec
}

func newHost() hostProvider { return &winHost{cache: map[int]procRec{}} }

func (h *winHost) Procs() (map[int]procRec, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	out := map[int]procRec{}
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		pid := int(pe.ProcessID)
		if pid == 0 {
			continue
		}
		name := windows.UTF16ToString(pe.ExeFile[:])
		hq, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe.ProcessID)
		if err != nil {
			out[pid] = procRec{PID: pid, PPID: int(pe.ParentProcessID), Name: name} // protected process: name only
			continue
		}
		var c, x, k, u windows.Filetime
		start := time.Time{}
		if windows.GetProcessTimes(hq, &c, &x, &k, &u) == nil {
			start = time.Unix(0, c.Nanoseconds()).UTC()
		}
		if r, ok := h.cache[pid]; ok && r.Start.Equal(start) {
			windows.CloseHandle(hq)
			out[pid] = r
			continue
		}
		r := procRec{PID: pid, PPID: int(pe.ParentProcessID), Name: name, Start: start}
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(hq, 0, &buf[0], &n) == nil {
			r.Exe = windows.UTF16ToString(buf[:n])
		}
		var tok windows.Token
		if windows.OpenProcessToken(hq, windows.TOKEN_QUERY, &tok) == nil {
			if tu, err := tok.GetTokenUser(); err == nil {
				if acct, dom, _, err := tu.User.Sid.LookupAccount(""); err == nil {
					r.User = dom + `\` + acct
				}
			}
			tok.Close()
		}
		windows.CloseHandle(hq)
		if hx, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pe.ProcessID); err == nil {
			r.Cmd = readCmdLine(hx)
			windows.CloseHandle(hx)
		}
		if r.Cmd != "" {
			if argv, err := windows.DecomposeCommandLine(r.Cmd); err == nil && len(argv) > 1 {
				r.Args = argv[1:]
			}
		}
		h.cache[pid] = r
		out[pid] = r
	}
	for pid := range h.cache { // forget exited processes
		if _, ok := out[pid]; !ok {
			delete(h.cache, pid)
		}
	}
	return out, nil
}

// readCmdLine reads the command line from the target's PEB. It fails quietly for protected
// processes and for 32-bit processes seen from a 64-bit agent.
func readCmdLine(h windows.Handle) string {
	var pbi windows.PROCESS_BASIC_INFORMATION
	var rl uint32
	if windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &rl) != nil || pbi.PebBaseAddress == nil {
		return ""
	}
	var peb windows.PEB
	if windows.ReadProcessMemory(h, uintptr(unsafe.Pointer(pbi.PebBaseAddress)), (*byte)(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), nil) != nil || peb.ProcessParameters == nil {
		return ""
	}
	var pp windows.RTL_USER_PROCESS_PARAMETERS
	if windows.ReadProcessMemory(h, uintptr(unsafe.Pointer(peb.ProcessParameters)), (*byte)(unsafe.Pointer(&pp)), unsafe.Sizeof(pp), nil) != nil {
		return ""
	}
	n := int(pp.CommandLine.Length / 2)
	if n == 0 || n > 32767 || pp.CommandLine.Buffer == nil {
		return ""
	}
	buf := make([]uint16, n)
	if windows.ReadProcessMemory(h, uintptr(unsafe.Pointer(pp.CommandLine.Buffer)), (*byte)(unsafe.Pointer(&buf[0])), uintptr(n)*2, nil) != nil {
		return ""
	}
	return strings.TrimSpace(windows.UTF16ToString(buf))
}

func (h *winHost) TCP() ([]connRec, error) {
	rows, err := otel.TCPTable()
	if err != nil {
		return nil, err
	}
	out := make([]connRec, 0, len(rows))
	for _, r := range rows {
		out = append(out, connRec{State: r.State, LocalIP: r.LocalIP.String(), LocalPort: int(r.LocalPort),
			RemoteIP: r.RemoteIP.String(), RemotePort: int(r.RemotePort), PID: int(r.PID)})
	}
	return out, nil
}
