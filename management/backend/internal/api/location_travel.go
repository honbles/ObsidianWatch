package api

import (
	"context"
	"fmt"
	"math"
	"time"
)

// F-17: impossible-travel and new-country detection from agent location
// history. Positions of managed devices are far less noisy than IP geo, but
// accuracy is still checked so a coarse (IP-based) fix does not trigger.
const (
	travelMinKm        = 300.0 // ignore hops shorter than this
	travelMaxSpeedKmh  = 900.0 // faster than an airliner
	travelMaxAccuracyM = 50000 // fixes worse than 50 km are not trusted
)

func haversineKm(lat1, lng1, lat2, lng2 float64) float64 {
	const r = 6371.0
	p := math.Pi / 180
	dLat, dLng := (lat2-lat1)*p, (lng2-lng1)*p
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*p)*math.Cos(lat2*p)*math.Sin(dLng/2)*math.Sin(dLng/2)
	return 2 * r * math.Asin(math.Min(1, math.Sqrt(a)))
}

func (e *AgentHealthEngine) checkLocationTravel(ctx context.Context) {
	hops, err := e.db.RecentLocationHops(ctx, time.Now().Add(-2*time.Hour))
	if err != nil {
		e.logger.Warn("location travel: query failed", "err", err)
		return
	}
	for _, h := range hops {
		if (h.Acc > travelMaxAccuracyM) || (h.PrevAcc > travelMaxAccuracyM) {
			continue
		}
		km := haversineKm(h.PrevLat, h.PrevLng, h.Lat, h.Lng)
		hours := h.TS.Sub(h.PrevTS).Hours()
		if hours < 1.0/60 {
			hours = 1.0 / 60
		}
		host := h.Host
		if host == "" {
			host = h.AgentID
		}
		if km >= travelMinKm && km/hours > travelMaxSpeedKmh {
			e.fire(ctx, fmt.Sprintf("loc:travel:%s:%d", h.AgentID, h.TS.Unix()),
				fmt.Sprintf("Impossible travel: %s", host),
				fmt.Sprintf("Device %s moved %.0f km in %s (%.0f km/h): %s (%s) to %s (%s).",
					host, km, h.TS.Sub(h.PrevTS).Round(time.Minute), km/hours,
					h.PrevCity, h.PrevCountry, h.City, h.Country),
				h.AgentID, host, 3)
			continue
		}
		if h.Country != "" && h.PrevCountry != "" && h.Country != h.PrevCountry && !h.CountryInPriorHistory {
			e.fire(ctx, fmt.Sprintf("loc:newcountry:%s:%s", h.AgentID, h.Country),
				fmt.Sprintf("Device in new country: %s", host),
				fmt.Sprintf("Device %s appeared in %s for the first time in 30 days (previously %s).",
					host, h.Country, h.PrevCountry),
				h.AgentID, host, 2)
		}
	}
}
