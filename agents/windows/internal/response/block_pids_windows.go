//go:build windows

package response

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"
)

// pidsByPath walks the process table natively (a PowerShell scan every second would be too heavy).
func pidsByPath(_ context.Context, path string) []int {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []int
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe.ProcessID)
		if e != nil {
			continue
		}
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil && samePath(windows.UTF16ToString(buf[:n]), path) {
			out = append(out, int(pe.ProcessID))
		}
		windows.CloseHandle(h)
	}
	return out
}
