package api

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// beaconNote flags a destination contacted at near-regular intervals - a
// beacon *candidate*, not a verdict (health checks and pollers look the same).
// Needs at least 6 contacts, a median interval of 5s or more, and low jitter
// (coefficient of variation <= 0.25).
func beaconNote(ts []time.Time) string {
	if len(ts) < 6 {
		return ""
	}
	t := append([]time.Time(nil), ts...)
	sort.Slice(t, func(i, j int) bool { return t[i].Before(t[j]) })
	var d []float64
	for i := 1; i < len(t); i++ {
		if g := t[i].Sub(t[i-1]).Seconds(); g > 0 {
			d = append(d, g)
		}
	}
	if len(d) < 5 {
		return ""
	}
	var sum float64
	for _, x := range d {
		sum += x
	}
	mean := sum / float64(len(d))
	var v float64
	for _, x := range d {
		v += (x - mean) * (x - mean)
	}
	cv := math.Sqrt(v/float64(len(d))) / mean
	s := append([]float64(nil), d...)
	sort.Float64s(s)
	med := s[len(s)/2]
	if med < 5 || cv > 0.25 {
		return ""
	}
	return fmt.Sprintf("beacon candidate: %d contacts about every %s (jitter %d%%)", len(ts), time.Duration(med*float64(time.Second)).Round(time.Second), int(cv*100))
}
