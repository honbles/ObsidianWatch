//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, val string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(val+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanUSB(t *testing.T) {
	root := t.TempDir()
	// root hub and an interface entry must be ignored
	writeFile(t, filepath.Join(root, "usb1"), "idVendor", "1d6b")
	writeFile(t, filepath.Join(root, "1-1:1.0"), "bInterfaceClass", "03")
	// a flash drive: class declared on the interface
	dev := filepath.Join(root, "1-2")
	writeFile(t, dev, "idVendor", "0781")
	writeFile(t, dev, "idProduct", "5567")
	writeFile(t, dev, "product", "Cruzer Blade")
	writeFile(t, dev, "serial", "ABC123")
	writeFile(t, dev, "bDeviceClass", "00")
	writeFile(t, filepath.Join(root, "1-2:1.0"), "bInterfaceClass", "08")
	got := scanUSB(root)
	if len(got) != 1 {
		t.Fatalf("want 1 device, got %d: %+v", len(got), got)
	}
	for _, d := range got {
		if !d.MassStorage || d.Product != "Cruzer Blade" || d.Serial != "ABC123" {
			t.Fatalf("bad parse: %+v", d)
		}
	}
}
