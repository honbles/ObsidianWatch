package runtimeinv

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func zipBytes(t *testing.T, files map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, b := range files {
		w, _ := zw.Create(name)
		_, _ = w.Write(b)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func TestInventory(t *testing.T) {
	proc := t.TempDir()
	fsRoot := t.TempDir()
	pid := filepath.Join(proc, "4242")
	_ = os.MkdirAll(pid, 0o755)

	// The process executable is a Go binary named "node" (so both the Go
	// build info and the Node working-directory tree are read).
	self, _ := os.Executable()
	b, _ := os.ReadFile(self)
	writeFile(t, filepath.Join(fsRoot, "usr/bin/node"), string(b))
	_ = os.Symlink(filepath.Join(fsRoot, "usr/bin/node"), filepath.Join(pid, "exe"))
	_ = os.Symlink(fsRoot, filepath.Join(pid, "root"))
	_ = os.Symlink("/app", filepath.Join(pid, "cwd"))

	// Java: an executable fat jar with its own coordinates and a nested jar.
	inner := zipBytes(t, map[string][]byte{"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": []byte("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n")})
	outer := zipBytes(t, map[string][]byte{
		"META-INF/maven/com.acme/shop/pom.properties": []byte("groupId=com.acme\nartifactId=shop\nversion=1.0.0\n"),
		"BOOT-INF/lib/log4j-core-2.14.1.jar":          inner,
		"BOOT-INF/lib/plain-3.2.jar":                  zipBytes(t, map[string][]byte{"x": []byte("y")}),
	})
	writeFile(t, filepath.Join(fsRoot, "app/shop.jar"), string(outer))

	// Python: a native extension of "yaml" is mapped; requests is installed.
	sp := filepath.Join(fsRoot, "venv/lib/python3.11/site-packages")
	writeFile(t, filepath.Join(sp, "PyYAML-6.0.dist-info/METADATA"), "Metadata-Version: 2.1\nName: PyYAML\nVersion: 6.0\n")
	writeFile(t, filepath.Join(sp, "PyYAML-6.0.dist-info/top_level.txt"), "_yaml\nyaml\n")
	writeFile(t, filepath.Join(sp, "requests-2.31.0.dist-info/METADATA"), "Name: requests\nVersion: 2.31.0\n")
	writeFile(t, filepath.Join(sp, "yaml/_yaml.cpython-311-x86_64-linux-gnu.so"), "elf")

	// Node: lockfile tree in the working directory, plus a mapped addon.
	writeFile(t, filepath.Join(fsRoot, "app/node_modules/.package-lock.json"),
		`{"packages":{"node_modules/lodash":{"version":"4.17.15"},"node_modules/@scope/x":{"version":"1.2.3"},"":{"version":"0"}}}`)
	writeFile(t, filepath.Join(fsRoot, "app/node_modules/bcrypt/package.json"), `{"name":"bcrypt","version":"5.0.0"}`)

	maps := "00400000-00401000 r-xp 00000000 08:01 1 /app/shop.jar\n" +
		"7f00-7f01 r-xp 00000000 08:01 2 /venv/lib/python3.11/site-packages/yaml/_yaml.cpython-311-x86_64-linux-gnu.so\n" +
		"7f02-7f03 r-xp 00000000 08:01 3 /app/node_modules/bcrypt/lib/binding/bcrypt_lib.node\n" +
		"7f04-7f05 rw-p 00000000 00:00 0 [heap]\n"
	writeFile(t, filepath.Join(pid, "maps"), maps)

	res, err := Inventory(proc, 4242)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range res.Packages {
		got[p.Ecosystem+":"+p.Name+"@"+p.Version] = p.Evidence
	}
	want := map[string]string{
		"Maven:com.acme:shop@1.0.0":                        "loaded",
		"Maven:org.apache.logging.log4j:log4j-core@2.14.1": "deployed",
		"Maven:plain@3.2":                                  "deployed",
		"PyPI:PyYAML@6.0":                                  "loaded",
		"PyPI:requests@2.31.0":                             "deployed",
		"npm:lodash@4.17.15":                               "deployed",
		"npm:@scope/x@1.2.3":                               "deployed",
		"npm:bcrypt@5.0.0":                                 "loaded",
	}
	for k, ev := range want {
		if got[k] != ev {
			t.Errorf("%s: got %q want %q", k, got[k], ev)
		}
	}
	goDeps := 0
	for _, p := range res.Packages {
		if p.Ecosystem == "Go" && p.Evidence == "loaded" {
			goDeps++
		}
	}
	if goDeps == 0 {
		t.Log("test binary carries no module deps; Go path exercised without packages")
	}
	_ = io.Discard
}

func TestDotnetDeps(t *testing.T) {
	proc := t.TempDir()
	fsRoot := t.TempDir()
	pid := filepath.Join(proc, "7")
	_ = os.MkdirAll(pid, 0o755)
	_ = os.Symlink(fsRoot, filepath.Join(pid, "root"))
	_ = os.Symlink("/srv/api", filepath.Join(pid, "cwd"))
	writeFile(t, filepath.Join(fsRoot, "srv/api/Api.deps.json"), `{
 "targets":{".NETCoreApp,Version=v8.0":{"Newtonsoft.Json/13.0.1":{"runtime":{"lib/net6.0/Newtonsoft.Json.dll":{}}},"Serilog/2.0.0":{"runtime":{"lib/net6.0/Serilog.dll":{}}}}},
 "libraries":{"Newtonsoft.Json/13.0.1":{"type":"package"},"Serilog/2.0.0":{"type":"package"},"Api/1.0.0":{"type":"project"}}}`)
	writeFile(t, filepath.Join(pid, "maps"), "7f-80 r--p 0 08:01 9 /srv/api/Newtonsoft.Json.dll\n")
	res, _ := Inventory(proc, 7)
	got := map[string]string{}
	for _, p := range res.Packages {
		got[p.Name+"@"+p.Version] = p.Evidence
	}
	if got["Newtonsoft.Json@13.0.1"] != "loaded" || got["Serilog@2.0.0"] != "deployed" || len(got) != 2 {
		t.Fatalf("dotnet: %+v", got)
	}
}
