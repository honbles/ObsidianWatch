//go:build !linux

package ebpf

import (
	"context"
)

// Sensor is not available off Linux; the type exists so shared code compiles everywhere.
type Sensor struct{}

func New(o Options) *Sensor                     { return &Sensor{} }
func (s *Sensor) Run(ctx context.Context) error { return ErrUnsupported }
func (s *Sensor) Mode() string                  { return "" }
func (s *Sensor) Stats() Stats                  { return Stats{} }
