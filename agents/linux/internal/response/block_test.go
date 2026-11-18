package response

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestBlockUnblock(t *testing.T) {
	dir := t.TempDir()
	h := New(filepath.Join(dir, "state"), nil, slog.Default())
	prog := filepath.Join(dir, "evil.sh")
	os.WriteFile(prog, []byte("#!/bin/sh\nsleep 30\n"), 0o755)

	r := h.block(context.Background(), Params{Path: prog})
	if !r.OK {
		t.Fatalf("block: %s", r.Message)
	}
	if st, _ := os.Stat(prog); st.Mode().Perm()&0o111 != 0 {
		t.Fatalf("file still executable: %v", st.Mode())
	}
	if l := h.listBlocked(); len(l.Data.(Table).Rows) != 1 {
		t.Fatalf("list: %+v", l)
	}
	if r := h.block(context.Background(), Params{Path: "/usr/bin/ls"}); r.OK {
		t.Fatal("system file must not be blockable")
	}
	if r := h.unblock(Params{Path: prog}); !r.OK {
		t.Fatalf("unblock: %s", r.Message)
	}
	if st, _ := os.Stat(prog); st.Mode().Perm() != 0o755 {
		t.Fatalf("mode not restored: %v", st.Mode())
	}
}

func TestEnforceKillsBlocked(t *testing.T) {
	dir := t.TempDir()
	h := New(filepath.Join(dir, "state"), nil, slog.Default())
	// a real copy of sleep we are allowed to run, then block it while running
	src, _ := os.ReadFile("/bin/sleep")
	prog := filepath.Join(dir, "blockme")
	os.WriteFile(prog, src, 0o755)
	cmd := newCmd(prog, "30")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start test program: ", err)
	}
	defer cmd.Process.Kill()
	r := h.block(context.Background(), Params{Path: prog})
	if !r.OK {
		t.Fatalf("block: %s", r.Message)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-timeAfter(5):
		t.Fatal("running instance was not ended")
	}
}
