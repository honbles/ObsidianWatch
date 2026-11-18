//go:build linux && !ebpf

package ebpf

import (
	"context"
	"errors"
)

// startKernel is the kernel-program tier. This build has none: it was built without the `ebpf` tag, so
// the sensor uses the proc-connector and polling tiers. See kernel_ebpf_linux.go and bpf/README.md.
func startKernel(ctx context.Context, s *Sensor) error {
	return errors.New("built without the ebpf tag (kernel programs not compiled in)")
}
