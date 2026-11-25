package collector

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func wstr(s string) []byte {
	u := append(utf16.Encode([]rune(s)), 0)
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

func startPayload(withFlags bool, image string) []byte {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[0:], 4242)
	binary.LittleEndian.PutUint64(b[4:], 133000000000000000) // 2022
	binary.LittleEndian.PutUint32(b[12:], 100)
	binary.LittleEndian.PutUint32(b[16:], 1)
	if withFlags {
		b = append(b, 0, 0, 0, 0)
	}
	b = append(b, wstr(image)...)
	return append(b, 1, 2, 3, 4) // checksum etc.
}

func TestParseETWProcessStartVersions(t *testing.T) {
	img := `\Device\HarddiskVolume3\Windows\System32\cmd.exe`
	for _, c := range []struct {
		version uint8
		flags   bool
	}{{0, false}, {3, true}, {0, true}, {3, false}} {
		s, ok := parseETWProcessStart(c.version, startPayload(c.flags, img))
		if !ok || s.PID != 4242 || s.PPID != 100 || s.Image != img || s.Created.Year() != 2022 {
			t.Errorf("v%d flags=%v: %+v", c.version, c.flags, s)
		}
	}
	if _, ok := parseETWProcessStart(3, []byte{1, 2}); ok {
		t.Error("short payload accepted")
	}
}

func TestParseETWProcessStop(t *testing.T) {
	b := make([]byte, 40)
	binary.LittleEndian.PutUint32(b[0:], 7)
	binary.LittleEndian.PutUint32(b[20:], 3)
	s, ok := parseETWProcessStop(b)
	if !ok || s.PID != 7 || s.ExitCode != 3 {
		t.Fatalf("%+v", s)
	}
}

func TestNtToDosPath(t *testing.T) {
	dev := map[string]string{`\Device\HarddiskVolume3`: "C:", `\Device\HarddiskVolume30`: "D:"}
	if got := ntToDosPath(`\Device\HarddiskVolume3\Windows\x.exe`, dev); got != `C:\Windows\x.exe` {
		t.Fatal(got)
	}
	if got := ntToDosPath(`\Device\HarddiskVolume30\y.exe`, dev); got != `D:\y.exe` {
		t.Fatal(got)
	}
	if baseName(`C:\Windows\x.exe`) != "x.exe" {
		t.Fatal("basename")
	}
}
