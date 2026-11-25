//go:build windows

package response

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi             = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSSendMessage = wtsapi.NewProc("WTSSendMessageW")
)

const (
	mbOK            = 0x0
	mbIconWarning   = 0x30
	mbSystemModal   = 0x1000
	mbSetForeground = 0x10000
)

// showNotice shows a message box in every active user session (the agent
// runs as SYSTEM in session 0 and cannot draw a window itself). It does not
// wait for the user and closes on its own after 5 minutes.
func showNotice(title, msg string) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	t, _ := windows.UTF16FromString(title)
	m, _ := windows.UTF16FromString(msg)
	for _, s := range unsafe.Slice(sessions, count) {
		if s.State != windows.WTSActive || s.SessionID == 0 {
			continue
		}
		var resp uint32
		procWTSSendMessage.Call(0, uintptr(s.SessionID),
			uintptr(unsafe.Pointer(&t[0])), uintptr(len(t)*2-2),
			uintptr(unsafe.Pointer(&m[0])), uintptr(len(m)*2-2),
			mbOK|mbIconWarning|mbSystemModal|mbSetForeground, 300, uintptr(unsafe.Pointer(&resp)), 0)
	}
}
