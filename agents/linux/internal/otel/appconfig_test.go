package otel_test

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"obsidianwatch/linux-agent/internal/config"
)

func TestAppConfigDecodeAndDefaults(t *testing.T) {
	var cfg config.Config
	err := yaml.Unmarshal([]byte(`
app_monitoring:
  enabled: true
  otlp:
    listen: "127.0.0.1:4318"
    socket: "/run/ow/otlp.sock"
  user_hash_key: "abc"
  client_ip_default: truncated
  client_ip_by_service:
    "billing|prod": off
  slow_ms_by_service:
    "api|prod": 300
  ebpf:
    enabled: true
    mode: procevent
    poll_interval: 3s
    environment: prod
    watch_dirs: ["/srv/app/uploads"]
`), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.AppMonitoring
	a.ApplyDefaults()
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if !a.Ebpf.Enabled || a.Ebpf.Mode != "procevent" || a.Ebpf.PollInterval != 3*time.Second || a.Ebpf.Environment != "prod" || len(a.Ebpf.WatchDirs) != 1 {
		t.Fatalf("sensor config: %+v", a.Ebpf)
	}
	if !a.Enabled || a.OTLP.Socket != "/run/ow/otlp.sock" || a.ClientIPByService["billing|prod"] != "off" || a.SlowMsByService["api|prod"] != 300 ||
		a.SlowMs != 1000 || a.MaxRoutesPerService != 2000 || a.FlushInterval != 30*time.Second || a.BaselineSamplePct != 1 {
		t.Fatalf("%+v", a)
	}
}

func TestAppConfigDefaultsOff(t *testing.T) {
	var cfg config.Config
	if cfg.AppMonitoring.Enabled {
		t.Fatal("must default to off")
	}
	var a config.AppMonitoringConfig
	a.ApplyDefaults()
	if a.OTLP.Listen != "127.0.0.1:4318" {
		t.Fatalf("default listen: %q", a.OTLP.Listen)
	}
}

func TestAppConfigRefusesRoutableListen(t *testing.T) {
	for _, l := range []string{"0.0.0.0:4318", ":4318", "[::]:4318", "10.0.0.5:4318", "example.com:4318", "nonsense"} {
		a := config.AppMonitoringConfig{Enabled: true, OTLP: config.OTLPConfig{Listen: l}}
		a.ApplyDefaults()
		if a.Validate() == nil {
			t.Fatalf("%q must be rejected", l)
		}
	}
	for _, l := range []string{"127.0.0.1:4318", "localhost:4318", "[::1]:4318"} {
		a := config.AppMonitoringConfig{OTLP: config.OTLPConfig{Listen: l}}
		a.ApplyDefaults()
		if err := a.Validate(); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
	}
	if m := (config.AppMonitoringConfig{Ebpf: config.EbpfConfig{Mode: "kernel"}}); func() bool { m.ApplyDefaults(); return m.Validate() == nil }() {
		t.Fatal("an unknown sensor mode must be refused")
	}
	if cfg0 := (config.AppMonitoringConfig{}); cfg0.Ebpf.Enabled {
		t.Fatal("the sensor is off by default")
	}
	bad := config.AppMonitoringConfig{ClientIPDefault: "hash"}
	bad.ApplyDefaults()
	if bad.Validate() == nil {
		t.Fatal("invalid client ip mode")
	}
	pct := config.AppMonitoringConfig{BaselineSamplePct: 150}
	pct.ApplyDefaults()
	if pct.Validate() == nil {
		t.Fatal("invalid sample pct")
	}
}
