//go:build !linux && !darwin

package ebpf

func newHost() hostProvider { return unsupportedHost{} }
