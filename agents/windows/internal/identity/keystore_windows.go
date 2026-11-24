//go:build windows

package identity

// On Windows the bundle is DPAPI-encrypted with the machine key, so a copy is
// useless on any other computer, and the file is readable only by SYSTEM and
// Administrators. Machine scope (rather than SYSTEM's user scope) lets an
// elevated "agent.exe install/uninstall" use the same identity as the
// service; Administrators can act as SYSTEM anyway.

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errNoBundle = errors.New("no stored identity")

type keyStore struct{ path string }

func newKeyStore(dir string) keyStore {
	return keyStore{path: filepath.Join(dir, "identity", "agent-identity.dpapi")}
}

var entropy = []byte("ObsidianWatch agent identity v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

func protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(plain), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE, &out); err != nil {
		return nil, err
	}
	return takeBlob(out), nil
}

func unprotect(enc []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(enc), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(out), nil
}

func (s keyStore) load() (bundle, error) {
	var b bundle
	enc, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return b, errNoBundle
	}
	if err != nil {
		return b, err
	}
	plain, err := unprotect(enc)
	if err != nil {
		return b, err
	}
	return b, json.Unmarshal(plain, &b)
}

func (s keyStore) save(b bundle) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// SYSTEM and Administrators only, no inheritance from ProgramData.
	_ = exec.Command("icacls", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").Run()
	plain, _ := json.Marshal(b)
	enc, err := protect(plain)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, enc, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s keyStore) remove() error {
	err := os.RemoveAll(filepath.Dir(s.path))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
