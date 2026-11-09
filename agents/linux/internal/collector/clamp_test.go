package collector

import "testing"

func TestClampTermDim(t *testing.T) {
	for _, c := range []struct{ in, def, want int }{{0, 30, 30}, {9, 30, 30}, {80, 30, 80}, {500, 30, 500}, {501, 30, 30}, {-5, 120, 120}} {
		if got := clampTermDim(c.in, c.def); got != c.want {
			t.Errorf("clampTermDim(%d,%d)=%d want %d", c.in, c.def, got, c.want)
		}
	}
}
