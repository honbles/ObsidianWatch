//go:build linux

package collector

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// The Go mirrors must match the C structs in bpf/proc.bpf.c byte for byte.
func TestKernelRecordSizes(t *testing.T) {
	for name, c := range map[string]struct{ got, want int }{
		"exec":    {binary.Size(kExec{}), 1352},
		"exit":    {binary.Size(kExit{}), 24},
		"connect": {binary.Size(kConn{}), 80},
	} {
		if c.got != c.want {
			t.Errorf("%s record is %d bytes, C struct is %d", name, c.got, c.want)
		}
	}
}

// The embedded object must parse and contain the programs and maps the
// loader attaches, so a stale or missing object fails here, not on a host.
func TestEmbeddedObject(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(procBPFObject))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"ow_exec", "ow_exit", "ow_connect"} {
		if spec.Programs[p] == nil {
			t.Errorf("program %s missing", p)
		}
	}
	for _, m := range []string{"events", "drops"} {
		if spec.Maps[m] == nil {
			t.Errorf("map %s missing", m)
		}
	}
}

func TestKernelEntryFromRecord(t *testing.T) {
	var e kExec
	e.PID, e.PPID, e.UID, e.StartNs, e.PStartNs = 42, 1, 1000, 5_000_000_000, 1_000_000_000
	copy(e.Comm[:], "curl")
	copy(e.Filename[:], "/usr/bin/curl")
	args := "curl\x00-s\x00http://x/a b\x00"
	copy(e.Args[:], args)
	e.ArgsLen = uint32(len(args))
	got := kernelEntry(&e)
	if got.name != "curl" || got.exe != "/usr/bin/curl" || len(got.args) != 3 || got.args[2] != "http://x/a b" {
		t.Fatalf("%+v", got)
	}
	if got.guid == "" || got.parentGUID == "" || got.source != "ebpf" {
		t.Fatalf("identity: %+v", got)
	}
	if want := bootID8() + "-42-500"; got.guid != want {
		t.Fatalf("guid %s, want %s", got.guid, want)
	}
}
