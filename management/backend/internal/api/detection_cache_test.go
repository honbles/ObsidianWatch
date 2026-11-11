package api

import (
	"testing"
	"time"
)

func TestDetectionInterval(t *testing.T) {
	t.Setenv("OW_DETECTION_INTERVAL_SECONDS", "")
	if detectionInterval() != 10*time.Second {
		t.Errorf("default should be 10s, got %v", detectionInterval())
	}
	for in, want := range map[string]time.Duration{"1": 2 * time.Second, "30": 30 * time.Second, "9999": 300 * time.Second, "abc": 10 * time.Second} {
		t.Setenv("OW_DETECTION_INTERVAL_SECONDS", in)
		if got := detectionInterval(); got != want {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
}
