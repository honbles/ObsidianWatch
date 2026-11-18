//go:build linux || darwin

package response

import (
	"context"
	"strconv"
)

// pidsByPath returns the PIDs whose executable path equals path.
func pidsByPath(ctx context.Context, path string) []int {
	cols, rows, err := qProcesses(ctx)
	if err != nil {
		return nil
	}
	pi, pa := -1, -1
	for i, c := range cols {
		switch c {
		case "pid":
			pi = i
		case "path":
			pa = i
		}
	}
	if pi < 0 || pa < 0 {
		return nil
	}
	var out []int
	for _, r := range rows {
		if pa < len(r) && pi < len(r) && samePath(r[pa], path) {
			if n, err := strconv.Atoi(r[pi]); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}
