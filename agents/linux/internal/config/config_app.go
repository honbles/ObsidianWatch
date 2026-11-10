package config

// config_app.go — OWNED BY THE APPLICATION BUILD. Extend this struct freely.
// Everything defaults to off: no eBPF sensor, no OTLP receiver.

type AppMonitoringConfig struct {
	Enabled bool `yaml:"enabled"`
}
