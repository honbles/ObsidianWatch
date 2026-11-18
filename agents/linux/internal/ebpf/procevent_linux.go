//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Netlink proc connector constants (linux/cn_proc.h, linux/connector.h).
const (
	netlinkConnector  = 11
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procEventExec     = 0x00000002
	procEventUID      = 0x00000004
)

// startProcEvent subscribes to exec and uid-change notifications from the kernel. It needs root in the
// initial pid namespace; where that is not so it returns an error and the sensor polls instead.
func (s *Sensor) startProcEvent(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, netlinkConnector)
	if err != nil {
		return fmt.Errorf("netlink connector socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("netlink connector bind: %w", err)
	}
	// nlmsghdr(16) + cn_msg(20) + op(4)
	const total = 16 + 20 + 4
	msg := make([]byte, total)
	binary.LittleEndian.PutUint32(msg[0:], total)
	binary.LittleEndian.PutUint16(msg[4:], unix.NLMSG_DONE)
	binary.LittleEndian.PutUint32(msg[12:], uint32(os.Getpid()))
	binary.LittleEndian.PutUint32(msg[16:], cnIdxProc)
	binary.LittleEndian.PutUint32(msg[20:], cnValProc)
	binary.LittleEndian.PutUint16(msg[32:], 4) // payload length
	binary.LittleEndian.PutUint32(msg[36:], procCnMcastListen)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("netlink connector subscribe: %w", err)
	}
	// A receive timeout lets the loop notice ctx cancellation without a wake-up channel.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	go s.procEventLoop(ctx, fd)
	return nil
}

func (s *Sensor) procEventLoop(ctx context.Context, fd int) {
	defer unix.Close(fd)
	buf := make([]byte, 8192)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if n < 36+16 {
			continue
		}
		what := binary.LittleEndian.Uint32(buf[36:])
		switch what {
		case procEventExec:
			if n >= 36+16+8 {
				s.onExec(int(binary.LittleEndian.Uint32(buf[36+16:])), "procevent")
			}
		case procEventUID:
			if n >= 36+16+16 {
				pid := int(binary.LittleEndian.Uint32(buf[36+16:]))
				euid := int(binary.LittleEndian.Uint32(buf[36+28:]))
				s.onUIDChange(pid, euid, "procevent")
			}
		}
	}
}
