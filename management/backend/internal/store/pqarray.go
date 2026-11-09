package store

import (
	"time"

	"github.com/lib/pq"
)

func pqStringArray(v []string) interface{} { return pq.Array(v) }

func pqInt64Array(v []int64) interface{} { return pq.Array(v) }
func pqTimeArray(v []time.Time) interface{} {
	s := make([]string, len(v))
	for i, t := range v {
		s[i] = t.UTC().Format(time.RFC3339Nano)
	}
	return pq.Array(s)
}
