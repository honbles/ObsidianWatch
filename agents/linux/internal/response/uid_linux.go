//go:build linux

package response

import (
	"io/fs"
	"os/user"
	"strconv"
	"syscall"
)

func uidName(st fs.FileInfo) string {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		u := strconv.Itoa(int(s.Uid))
		if lu, err := user.LookupId(u); err == nil {
			return lu.Username
		}
		return u
	}
	return ""
}
