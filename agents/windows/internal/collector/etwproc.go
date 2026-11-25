package collector

// etwproc.go - decoding of Microsoft-Windows-Kernel-Process payloads. Kept
// free of Windows APIs so it is tested on any OS.
//
// ProcessStart (event 1) user data, by template version:
//   v0:  ProcessID u32, CreateTime FILETIME, ParentProcessID u32, SessionID u32, ImageName wstring
//   v1+: ProcessID u32, CreateTime FILETIME, ParentProcessID u32, SessionID u32, Flags u32, ImageName wstring, ...
// ProcessStop (event 2) user data starts:
//   ProcessID u32, CreateTime FILETIME, ExitTime FILETIME, ExitCode u32, ...
// ImageName is an NT path such as \Device\HarddiskVolume3\Windows\System32\cmd.exe.

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

type etwProcStart struct {
	PID, PPID, Session uint32
	Created            time.Time
	Image              string // NT path
}

type etwProcStop struct {
	PID      uint32
	ExitCode uint32
	Created  time.Time
}

// filetimeToTime converts 100 ns intervals since 1601 to time.Time.
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000 // 1601 to 1970 in 100 ns
	if ft < epochDiff {
		return time.Time{}
	}
	return time.Unix(0, int64(ft-epochDiff)*100).UTC()
}

// utf16z reads a NUL-terminated UTF-16LE string from b.
func utf16z(b []byte) (string, bool) {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			return string(utf16.Decode(u)), true
		}
		u = append(u, c)
	}
	return "", false
}

func parseETWProcessStart(version uint8, b []byte) (etwProcStart, bool) {
	var s etwProcStart
	if len(b) < 20 {
		return s, false
	}
	s.PID = binary.LittleEndian.Uint32(b[0:])
	s.Created = filetimeToTime(binary.LittleEndian.Uint64(b[4:]))
	s.PPID = binary.LittleEndian.Uint32(b[12:])
	s.Session = binary.LittleEndian.Uint32(b[16:])
	// The image name follows SessionID (v0) or Flags (v1+). Try the
	// documented offset first and accept the other only if it yields a path.
	offsets := []int{24, 20}
	if version == 0 {
		offsets = []int{20, 24}
	}
	for _, off := range offsets {
		if off >= len(b) {
			continue
		}
		if img, ok := utf16z(b[off:]); ok && len(img) > 0 && (img[0] == '\\' || (len(img) > 2 && img[1] == ':')) {
			s.Image = img
			return s, true
		}
	}
	return s, true // pid and parent are still useful without the image
}

func parseETWProcessStop(b []byte) (etwProcStop, bool) {
	var s etwProcStop
	if len(b) < 24 {
		return s, false
	}
	s.PID = binary.LittleEndian.Uint32(b[0:])
	s.Created = filetimeToTime(binary.LittleEndian.Uint64(b[4:]))
	s.ExitCode = binary.LittleEndian.Uint32(b[20:])
	return s, true
}

// ntToDosPath maps \Device\HarddiskVolumeN\x to C:\x using a device table
// (device name -> drive letter), as returned by QueryDosDevice.
func ntToDosPath(p string, devices map[string]string) string {
	for dev, drive := range devices {
		if len(p) > len(dev) && p[:len(dev)] == dev && p[len(dev)] == '\\' {
			return drive + p[len(dev):]
		}
	}
	return p
}

// baseName returns the file name of a Windows path.
func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
