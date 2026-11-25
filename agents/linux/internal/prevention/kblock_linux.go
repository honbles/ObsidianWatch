//go:build linux

package prevention

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate sh bpf/build.sh
//go:embed bpf/block_bpfel.o
var blockBPFObject []byte

// kernelBlock refuses connect()/sendmsg() to listed addresses in the kernel.
type kernelBlock struct {
	mu     sync.Mutex
	coll   *ebpf.Collection
	links  []link.Link
	rd     *ringbuf.Reader
	cur4   map[uint32]bool
	cur6   map[[16]byte]bool
	mount  string // cgroup2 mount we created, unmounted on Close
	engine *Engine
}

// cgroup2Root finds the cgroup v2 mount, mounting one under the agent's
// state directory when the host only has cgroup v1 mounted.
func cgroup2Root(stateDir string) (path string, ours bool, err error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// ... mountpoint ... - fstype source opts
			l := sc.Text()
			i := strings.Index(l, " - ")
			if i < 0 {
				continue
			}
			pre, post := strings.Fields(l[:i]), strings.Fields(l[i+3:])
			if len(pre) >= 5 && len(post) >= 1 && post[0] == "cgroup2" {
				f.Close()
				return pre[4], false, nil
			}
		}
		f.Close()
	}
	dir := stateDir + "/cgroup2"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false, err
	}
	if err := syscall.Mount("none", dir, "cgroup2", 0, ""); err != nil {
		return "", false, fmt.Errorf("no cgroup2 mount and cannot mount one: %w", err)
	}
	return dir, true, nil
}

// StartKernelBlocker loads and attaches the programs. On error nothing is
// left attached and the engine falls back to block_ip.
func StartKernelBlocker(e *Engine) (KernelBlocker, error) {
	if os.Getenv("OW_DISABLE_EBPF") == "1" {
		return nil, errors.New("disabled by OW_DISABLE_EBPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}
	root, ours, err := cgroup2Root(e.dir)
	if err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(blockBPFObject))
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		if ours {
			syscall.Unmount(root, 0)
		}
		return nil, fmt.Errorf("load: %w", err)
	}
	k := &kernelBlock{coll: coll, cur4: map[uint32]bool{}, cur6: map[[16]byte]bool{}, engine: e}
	if ours {
		k.mount = root
	}
	for _, a := range []struct {
		prog string
		at   ebpf.AttachType
	}{
		{"ow_connect4", ebpf.AttachCGroupInet4Connect},
		{"ow_connect6", ebpf.AttachCGroupInet6Connect},
		{"ow_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg},
		{"ow_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: root, Attach: a.at, Program: coll.Programs[a.prog]})
		if err != nil {
			k.Close()
			return nil, fmt.Errorf("attach %s: %w", a.prog, err)
		}
		k.links = append(k.links, l)
	}
	if k.rd, err = ringbuf.NewReader(coll.Maps["blocks"]); err != nil {
		k.Close()
		return nil, err
	}
	go k.readBlocks()
	return k, nil
}

func (k *kernelBlock) Replace(ips []netip.Addr) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.coll == nil {
		return errors.New("closed")
	}
	want4 := map[uint32]bool{}
	want6 := map[[16]byte]bool{}
	for _, a := range ips {
		if a.Is4() {
			b := a.As4()
			want4[binary.LittleEndian.Uint32(b[:])] = true // the kernel field is network order; read as stored bytes
		} else {
			want6[a.As16()] = true
		}
	}
	one := uint8(1)
	m4, m6 := k.coll.Maps["blocked4"], k.coll.Maps["blocked6"]
	for key := range k.cur4 {
		if !want4[key] {
			_ = m4.Delete(key)
		}
	}
	for key := range want4 {
		if !k.cur4[key] {
			if err := m4.Put(key, one); err != nil {
				return err
			}
		}
	}
	for key := range k.cur6 {
		if !want6[key] {
			_ = m6.Delete(key)
		}
	}
	for key := range want6 {
		if !k.cur6[key] {
			if err := m6.Put(key, one); err != nil {
				return err
			}
		}
	}
	k.cur4, k.cur6 = want4, want6
	return nil
}

func (k *kernelBlock) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.rd != nil {
		k.rd.Close()
	}
	for _, l := range k.links {
		l.Close()
	}
	k.links = nil
	if k.coll != nil {
		k.coll.Close()
		k.coll = nil
	}
	if k.mount != "" {
		_ = syscall.Unmount(k.mount, 0)
		k.mount = ""
	}
}

type blockRec struct {
	PID, Family, Port, Proto uint32
	Addr                     [16]byte
	Comm                     [16]byte
}

// readBlocks turns refused connects into prevention reports.
func (k *kernelBlock) readBlocks() {
	for {
		rec, err := k.rd.Read()
		if err != nil {
			return
		}
		var b blockRec
		if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &b) != nil {
			continue
		}
		var a netip.Addr
		if b.Family == 2 {
			a = netip.AddrFrom4([4]byte(b.Addr[:4]))
		} else {
			a = netip.AddrFrom16(b.Addr).Unmap()
		}
		k.engine.kernelRefused(a, int(b.PID), int(b.Port), b.Proto, string(bytes.TrimRight(b.Comm[:], "\x00")))
	}
}

// kernelRefused reports one refused connection (once per address and
// process per 10 minutes).
func (e *Engine) kernelRefused(a netip.Addr, pid, port int, proto uint32, comm string) {
	if e.seen(fmt.Sprintf("kblock|%s|%d", a, pid)) {
		return
	}
	e.mu.RLock()
	x := e.ips[a]
	e.mu.RUnlock()
	r := e.report("ip", a.String(), x, Enforce)
	r.pid = pid
	r.Fields["pid"], r.Fields["dst_ip"], r.Fields["dst_port"] = pid, a.String(), port
	r.Fields["proto"] = map[uint32]string{6: "tcp", 17: "udp"}[proto]
	r.Fields["enforced_by"] = "kernel"
	r.proc = comm // from the kernel: the process may already be gone
	if pid > 0 {
		r.image, _ = os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
		if c, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); err == nil {
			r.cmd = strings.TrimSpace(strings.ReplaceAll(string(c), "\x00", " "))
		}
	}
	e.emit(r, "blocked", "connection refused before it was made")
}

// sweepProcesses hashes every running process image once (when a new set
// arrives) and handles matches like a new process start.
func (e *Engine) sweepProcesses() {
	ents, _ := os.ReadDir("/proc")
	hashed := map[string]string{}
	for _, d := range ents {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		exe, err := os.Readlink("/proc/" + d.Name() + "/exe")
		if err != nil || exe == "" {
			continue
		}
		sum, ok := hashed[exe]
		if !ok {
			sum, _ = hashPath("/proc/" + d.Name() + "/exe")
			hashed[exe] = sum
		}
		if sum == "" {
			continue
		}
		if _, ok := e.lookupHash(sum); ok {
			comm, _ := os.ReadFile("/proc/" + d.Name() + "/comm")
			e.processMatch(pid, strings.TrimSpace(string(comm)), exe, sum, "running_process")
		}
		time.Sleep(time.Millisecond) // stay gentle on busy hosts
	}
}
