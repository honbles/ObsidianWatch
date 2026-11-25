//go:build !linux

package prevention

import "errors"

// StartKernelBlocker has no kernel tier outside Linux: IP matches are
// blocked with the block_ip response action after the connection is seen.
func StartKernelBlocker(e *Engine) (KernelBlocker, error) {
	return nil, errors.New("kernel blocking is Linux only")
}

// sweepProcesses is not implemented outside Linux yet: running processes
// are checked when they start (process events carry the image hash).
func (e *Engine) sweepProcesses() {}
