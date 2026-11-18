//go:build !linux && !windows

package ebpf

func newHost() hostProvider { return unsupportedHost{} }
