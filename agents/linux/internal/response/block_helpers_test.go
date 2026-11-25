package response

import (
	"os/exec"
	"time"
)

func newCmd(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }
func timeAfter(s int) <-chan time.Time             { return time.After(time.Duration(s) * time.Second) }
