package ownproc

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOwnDescendants(t *testing.T) {
	self := os.Getpid()
	if !IsOwn(40001, self) {
		t.Fatal("direct child of the agent is own")
	}
	if !IsOwn(40002, 40001) {
		t.Fatal("grandchild of the agent is own")
	}
	if !IsOwn(40001, 0) {
		t.Fatal("later events for a known own pid (no ppid) are own")
	}
	if IsOwn(50001, 49999) {
		t.Fatal("unrelated process must not be own")
	}
	Exclude(60001)
	if IsOwn(60001, self) || IsOwn(60002, 60001) {
		t.Fatal("live-response shell and its children are not own")
	}
	if IsOwn(0, self) {
		t.Fatal("pid 0 is never own")
	}
}

func TestTagRaw(t *testing.T) {
	out := TagRaw(json.RawMessage(`{"a":1}`))
	var m map[string]any
	if json.Unmarshal(out, &m) != nil || m["self_activity"] != true || m["a"] != float64(1) {
		t.Fatalf("bad tag: %s", out)
	}
	if o := TagRaw(nil); len(o) == 0 {
		t.Fatal("nil raw must still produce a tagged object")
	}
}
