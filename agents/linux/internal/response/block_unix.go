//go:build linux || darwin

package response

import "os"

// denyExec removes every execute bit and returns the original permission bits.
func denyExec(path string) (uint32, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	mode := st.Mode().Perm()
	if mode&0o111 == 0 { // already non-executable: keep what we recorded earlier
		return uint32(mode), nil
	}
	return uint32(mode), os.Chmod(path, mode&^0o111)
}

func allowExec(path string, mode uint32) error {
	if mode == 0 {
		mode = 0o755
	}
	return os.Chmod(path, os.FileMode(mode))
}
