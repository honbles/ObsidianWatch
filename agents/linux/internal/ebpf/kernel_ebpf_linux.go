//go:build linux && ebpf

package ebpf

// kernel_ebpf_linux.go - the kernel-program tier. Built only with `-tags ebpf`, which needs
// github.com/cilium/ebpf and the files `go generate` produces from bpf/sensor.bpf.c (see bpf/README.md).
// NOT COMPILED OR RUN in the environment this was written in: no clang, no cilium/ebpf module.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target amd64,arm64 sensor bpf/sensor.bpf.c -- -I./bpf

// Event types (keep in step with enum evtype in bpf/sensor.bpf.c).
const (
	evExec    = 1
	evConnect = 2
	evOpen    = 3
	evPriv    = 4
	evEscape  = 5
)

// rawEvent mirrors struct event in bpf/sensor.bpf.c byte for byte.
type rawEvent struct {
	Type, PID, PPID, UID, Aux uint32
	SPort, DPort              uint16
	Family                    uint8
	_                         [3]uint8
	SAddr, DAddr              uint32
	FName                     [128]byte
}

func startKernel(ctx context.Context, s *Sensor) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	var objs sensorObjects
	if err := loadSensorObjects(&objs, nil); err != nil {
		return fmt.Errorf("load kernel programs: %w", err)
	}
	var links []link.Link
	for _, a := range []struct {
		group, name string
		prog        func() (link.Link, error)
	}{
		{"sched", "sched_process_fork", func() (link.Link, error) { return link.Tracepoint("sched", "sched_process_fork", objs.HandleFork, nil) }},
		{"sched", "sched_process_exit", func() (link.Link, error) { return link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil) }},
		{"sched", "sched_process_exec", func() (link.Link, error) { return link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil) }},
		{"sock", "inet_sock_set_state", func() (link.Link, error) {
			return link.Tracepoint("sock", "inet_sock_set_state", objs.HandleConnect, nil)
		}},
		{"syscalls", "sys_enter_openat", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
		}},
		{"syscalls", "sys_enter_setuid", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_setuid", objs.HandleSetuid, nil)
		}},
		{"syscalls", "sys_enter_mount", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_mount", objs.HandleMount, nil)
		}},
		{"syscalls", "sys_enter_setns", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_setns", objs.HandleSetns, nil)
		}},
	} {
		l, err := a.prog()
		if err != nil {
			for _, x := range links {
				x.Close()
			}
			objs.Close()
			return fmt.Errorf("attach %s/%s: %w", a.group, a.name, err)
		}
		links = append(links, l)
	}
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, x := range links {
			x.Close()
		}
		objs.Close()
		return fmt.Errorf("open ring buffer: %w", err)
	}
	s.procActive = true // exec events come from the kernel: the /proc process poller would only duplicate them

	// Keep the kernel's watch map equal to the registry (children are added in the kernel by the fork hook).
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				for _, pid := range s.reg.PIDs() {
					one := uint8(1)
					_ = objs.Watched.Put(uint32(pid), one)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		rd.Close() // unblocks Read
		for _, x := range links {
			x.Close()
		}
		objs.Close()
	}()
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				return
			}
			var e rawEvent
			if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e) != nil {
				continue
			}
			s.onKernelEvent(e)
		}
	}()
	return nil
}

// onKernelEvent turns a kernel event into an agent event. Ancestry, command line and container id are
// read from /proc by pid, exactly as in the fallback tiers, so every tier produces the same raw.proc.
func (s *Sensor) onKernelEvent(e rawEvent) {
	pid := int(e.PID)
	d, err := s.fs.full(pid)
	if err != nil {
		return // the process already exited
	}
	switch e.Type {
	case evExec:
		s.emit(ProcessEvent(&s.o, "ebpf", d.ProcInfo, nil), &s.nProc)
	case evConnect:
		dst := net.IPv4(byte(e.DAddr), byte(e.DAddr>>8), byte(e.DAddr>>16), byte(e.DAddr>>24)).String()
		src := net.IPv4(byte(e.SAddr), byte(e.SAddr>>8), byte(e.SAddr>>16), byte(e.SAddr>>24)).String()
		s.emit(NetworkEvent(&s.o, "ebpf", d.ProcInfo, dst, int(e.DPort), src, int(e.SPort), "", nil), &s.nNet)
	case evOpen:
		path := strings.TrimRight(string(e.FName[:]), "\x00")
		op := "read"
		if e.Aux&(0x1|0x2|0x40) != 0 { // O_WRONLY | O_RDWR | O_CREAT
			op = "write"
		}
		s.emit(FileEvent(&s.o, "ebpf", d.ProcInfo, path, op, ""), &s.nFile)
	case evPriv:
		s.emit(ProcessEvent(&s.o, "ebpf", d.ProcInfo, &Priv{Kind: "setuid", Detail: fmt.Sprint(e.Aux)}), &s.nPriv)
	case evEscape:
		kind := map[uint32]string{1: "mount", 2: "setns", 3: "unshare"}[e.Aux]
		if kind != "" {
			s.emit(EscapeEvent(&s.o, "ebpf", d.ProcInfo, kind), &s.nProc)
		}
	}
}
