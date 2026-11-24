//go:build !windows

package identity

// On Linux and macOS the bundle is a root-only file (0600 in a 0700
// directory). The macOS Keychain is not used because the only way to write
// to it without cgo is the `security` tool, which takes the secret on its
// command line where other local users can read it.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

var errNoBundle = errors.New("no stored identity")

type keyStore struct{ path string }

func newKeyStore(dir string) keyStore {
	return keyStore{path: filepath.Join(dir, "identity", "agent-identity.json")}
}

func (s keyStore) load() (bundle, error) {
	var b bundle
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return b, errNoBundle
	}
	if err != nil {
		return b, err
	}
	return b, json.Unmarshal(data, &b)
}

func (s keyStore) save(b bundle) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(s.path), 0o700)
	data, _ := json.Marshal(b)
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
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
