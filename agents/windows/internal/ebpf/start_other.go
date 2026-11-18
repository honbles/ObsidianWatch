//go:build !linux

package ebpf

// On platforms without /proc the sensor is the polling tier (poll_sensor.go) fed by the OS-specific
// snapshot provider (host_<os>.go).
type Sensor = pollSensor

func New(o Options) *Sensor { return newPollSensor(o, newHost()) }

// unsupportedHost is used on platforms with no snapshot provider.
type unsupportedHost struct{}

func (unsupportedHost) Procs() (map[int]procRec, error) { return nil, ErrUnsupported }
func (unsupportedHost) TCP() ([]connRec, error)         { return nil, ErrUnsupported }
func (unsupportedHost) unsupported() bool               { return true }
