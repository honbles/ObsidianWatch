# Kernel tier (eBPF) - build and verification

**Status: written, not built.** `sensor.bpf.c` and `../kernel_ebpf_linux.go` were produced in an environment with no clang, no
libbpf headers and no `github.com/cilium/ebpf` module, so neither has been compiled or loaded. The default build (no tag) does not
include them; the sensor then uses the proc-connector and polling tiers, which are built and tested.

## Build
Needs: clang >= 12, bpftool, Linux headers with BTF (`/sys/kernel/btf/vmlinux`), Go with `github.com/cilium/ebpf`.

    cd agents/linux/internal/ebpf
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
    go get github.com/cilium/ebpf@<pinned version>     # adds a dependency: list it in the manifest
    go generate ./...                                   # produces sensor_bpfel.go/.o (commit them with the pinned version)
    go build -tags ebpf ./...

## Verify before relying on it (checklist)
1. `go vet -tags ebpf ./...` compiles (the Go loader was never type-checked against the library).
2. Run the agent as root with `app_monitoring.ebpf.mode: ebpf`; the log says `host sensor running mode=ebpf`.
3. Start a test service, `sh -c id` from it: a `process` event with source `ebpf` and `ancestors` appears.
4. Same service opens `/etc/shadow` (`cat`): a `file` event with `op: read`.
5. Service connects out: a `network` event with the right destination.
6. A watched process calls `setuid`: `raw.proc.priv_change`; `unshare -m` / `nsenter`: `raw.proc.escape`.
7. Event volume stays inside the per-second budget on a busy host; `ringbuf` drops are zero.

## Known limits of this version
IPv4 only for connections; `openat` only (not `open`, `openat2`, `creat`); `setuid` only (not `setresuid`, `capset`); no `unshare` hook yet.
