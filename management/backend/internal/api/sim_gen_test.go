package api

// Generates the alert-verification scripts in tools/simulate from the
// signature fixtures, so the scripts always match the engine:
//
//	OW_UPDATE_SIM=1 go test ./internal/api -run TestSimScriptsUpToDate
//
// A fixture becomes a script test only if the engine would actually fire on
// the harmless look-alike the script runs (echo of the command text, or a
// temporary HKCU Run value). Everything else is listed as skipped.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

type simCase struct {
	ID, Title string
	Kind      string // proc | named | reg
	Name      string // named: executable name the stand-in is copied to
	Words     []string
	RegPath   string // reg: PowerShell registry parent path
	RegData   string
}

type simSkip struct{ ID, Reason string }

const winExe = `"C:\Windows\system32\cmd.exe"`

func titleOf(s ThreatSig) string { return fmt.Sprintf("[%s] %s", s.MITRE, s.Name) }

var safeExeName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,40}$`)

// namedWords returns the arguments for a stand-in executable named like the
// fixture's process, or ok=false if the fixture has no usable name.
func namedWords(fire store.Event) (name string, args []string, ok bool) {
	if fire.ProcessName == nil || fire.CommandLine == nil || !safeExeName.MatchString(*fire.ProcessName) {
		return "", nil, false
	}
	name = *fire.ProcessName
	words := strings.Fields(*fire.CommandLine)
	if len(words) > 0 {
		first := strings.ToLower(words[0])
		first = first[strings.LastIndexAny(first, `/\`)+1:]
		if first == strings.ToLower(name) || first == strings.ToLower(strings.TrimSuffix(name, ".exe")) {
			words = words[1:]
		}
	}
	return name, words, true
}

// buildSimCases returns the verified cases for one OS prefix (W-, L-, M-).
func buildSimCases(prefix string) ([]simCase, []simSkip) {
	var cases []simCase
	var skips []simSkip
	seen := map[string]bool{}
	for _, fx := range sigFixtures {
		if !strings.HasPrefix(fx.ID, prefix) || seen[fx.ID] {
			continue
		}
		sig, ok := fxFind(fx.ID)
		if !ok {
			continue
		}
		fire := fx.Fire
		switch {
		case fire.EventType == "process" && fire.CommandLine != nil && (fire.EventID == nil):
			words := strings.Fields(*fire.CommandLine)
			text := strings.Join(words, " ")
			if prefix == "W-" {
				echoOK := !strings.ContainsAny(text, "\"%^|&<>")
				if echoOK {
					cl := winExe + " /c echo OWSIM-0000 " + text
					n, c := "cmd.exe", cl
					echoOK = sig.Match(store.Event{EventType: "process", ProcessName: &n, CommandLine: &c})
				}
				if !echoOK {
					name, args, ok := namedWords(fire)
					if ok && !strings.Contains(strings.Join(args, " "), "\"") {
						exe := name
						if !strings.HasSuffix(strings.ToLower(exe), ".exe") {
							exe += ".exe"
						}
						cl := `C:\Users\x\AppData\Local\Temp\owsim-0000\` + exe + " " + strings.Join(args, " ") + " OWSIM-0000"
						n, c := exe, cl
						ok = sig.Match(store.Event{EventType: "process", ProcessName: &n, CommandLine: &c})
						if ok {
							cases = append(cases, simCase{ID: fx.ID, Title: titleOf(sig), Kind: "named", Name: exe, Words: args})
							seen[fx.ID] = true
							continue
						}
					}
					skips = append(skips, simSkip{fx.ID, "needs the real process or event; a harmless stand-in does not trigger it"})
					continue
				}
			} else {
				echoOK := false
				{
					cl := "/bin/echo OWSIM-0000 " + text
					n, c := "echo", cl
					echoOK = sig.Match(store.Event{EventType: "process", ProcessName: &n, CommandLine: &c})
				}
				if !echoOK {
					name, args, ok := namedWords(fire)
					if ok {
						cl := "/var/tmp/owsim-0000/" + name + " " + strings.Join(args, " ") + " OWSIM-0000"
						n, c := name, cl
						if sig.Match(store.Event{EventType: "process", ProcessName: &n, CommandLine: &c}) {
							cases = append(cases, simCase{ID: fx.ID, Title: titleOf(sig), Kind: "named", Name: name, Words: args})
							seen[fx.ID] = true
							continue
						}
					}
					skips = append(skips, simSkip{fx.ID, "needs the real process or event; a harmless stand-in does not trigger it"})
					continue
				}
			}
			cases = append(cases, simCase{ID: fx.ID, Title: titleOf(sig), Kind: "proc", Words: words})
			seen[fx.ID] = true
		case prefix == "W-" && fire.EventType == "registry" && fire.RegKey != nil && strings.HasPrefix(strings.ToUpper(*fire.RegKey), `HKCU\`):
			data := ""
			if fire.RegValue != nil {
				data = *fire.RegValue
			}
			parts := strings.Split(*fire.RegKey, `\`)
			parent := strings.Join(parts[:len(parts)-1], `\`)
			simKey := `HKU\S-1-5-21-0\` + strings.TrimPrefix(parent, `HKCU\`) + `\OWSIM-0000`
			ev := store.Event{EventType: "registry", RegKey: &simKey, RegValue: &data}
			if strings.ContainsAny(data, "'\"") || !sig.Match(ev) {
				skips = append(skips, simSkip{fx.ID, "registry simulation would not trigger the rule"})
				continue
			}
			cases = append(cases, simCase{ID: fx.ID, Title: titleOf(sig), Kind: "reg",
				RegPath: strings.Replace(parent, `HKCU\`, `HKCU:\`, 1), RegData: data})
			seen[fx.ID] = true
		default:
			skips = append(skips, simSkip{fx.ID, "needs a real " + fire.EventType + " event (log, file or system change)"})
		}
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	sort.Slice(skips, func(i, j int) bool { return skips[i].ID < skips[j].ID })
	return cases, skips
}

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func jsonNeedle(title string) string {
	b, _ := json.Marshal(title) // same escaping the API applies
	return string(b)
}

func genWindows() string {
	cases, skips := buildSimCases("W-")
	var b strings.Builder
	b.WriteString(psHeader)
	b.WriteString("$Cases = @(\n")
	for _, c := range cases {
		if c.Kind == "proc" {
			fmt.Fprintf(&b, "  @{ Id=%s; Title=%s; Kind='proc'; Text=%s }\n", psq(c.ID), psq(c.Title), psq(strings.Join(c.Words, " ")))
		} else if c.Kind == "named" {
			fmt.Fprintf(&b, "  @{ Id=%s; Title=%s; Kind='named'; Name=%s; Text=%s }\n", psq(c.ID), psq(c.Title), psq(c.Name), psq(strings.Join(c.Words, " ")))
		} else {
			fmt.Fprintf(&b, "  @{ Id=%s; Title=%s; Kind='reg'; Path=%s; Data=%s }\n", psq(c.ID), psq(c.Title), psq(c.RegPath), psq(c.RegData))
		}
	}
	b.WriteString(")\n$Skipped = @(\n")
	for _, s := range skips {
		fmt.Fprintf(&b, "  @{ Id=%s; Reason=%s }\n", psq(s.ID), psq(s.Reason))
	}
	b.WriteString(")\n")
	b.WriteString(psBody)
	return b.String()
}

func genUnix(osName, prefix string) string {
	cases, skips := buildSimCases(prefix)
	var b strings.Builder
	b.WriteString(strings.ReplaceAll(shHeader, "@@OS@@", osName))
	for _, c := range cases {
		fn := "T"
		if c.Kind == "named" {
			fn = "N"
		}
		line := []string{fn, shq(c.ID), shq(c.Title), shq(jsonNeedle(c.Title))}
		if c.Kind == "named" {
			line = append(line, shq(c.Name))
		}
		for _, w := range c.Words {
			line = append(line, shq(w))
		}
		b.WriteString(strings.Join(line, " ") + "\n")
	}
	for _, s := range skips {
		fmt.Fprintf(&b, "S %s\n", shq(s.ID+": "+s.Reason))
	}
	b.WriteString(shBody)
	return b.String()
}

func simFiles() map[string]string {
	return map[string]string{
		"ow-simulate-windows.ps1": genWindows(),
		"ow-simulate-linux.sh":    genUnix("Linux", "L-"),
		"ow-simulate-macos.sh":    genUnix("macOS", "M-"),
	}
}

func TestSimScriptsUpToDate(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "tools", "simulate")
	for name, want := range simFiles() {
		path := filepath.Join(dir, name)
		if os.Getenv("OW_UPDATE_SIM") == "1" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(want), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Errorf("%s is stale; regenerate with OW_UPDATE_SIM=1 go test ./internal/api -run TestSimScriptsUpToDate", name)
		}
	}
}

func TestSimCasesAreSafeAndNonTrivial(t *testing.T) {
	for _, p := range []string{"W-", "L-", "M-"} {
		cases, _ := buildSimCases(p)
		if len(cases) < 5 {
			t.Errorf("%s: only %d simulable cases", p, len(cases))
		}
		for _, c := range cases {
			if c.Kind == "proc" && p == "W-" && strings.ContainsAny(strings.Join(c.Words, " "), "\"%^|&<>") {
				t.Errorf("%s: unsafe metacharacters in %q", c.ID, c.Words)
			}
		}
	}
}
