package ebpf

import (
	"path"
	"regexp"
	"strings"
)

var (
	versionSuffix = regexp.MustCompile(`[-_.]v?\d+(\.\d+)*([-_.][A-Za-z0-9]+)?$`)
	badNameChars  = regexp.MustCompile(`[^A-Za-z0-9._\-]`)
	genericNames  = map[string]bool{"index": true, "server": true, "app": true, "main": true, "start": true, "run": true, "manage": true, "wsgi": true, "asgi": true, "cli": true}
)

func cleanName(s string) string {
	s = badNameChars.ReplaceAllString(s, "")
	s = strings.Trim(s, "._-")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// norm lets Windows paths (backslashes) be handled like Unix ones.
func norm(p string) string { return strings.ReplaceAll(p, `\`, "/") }

func stripExt(p string) string {
	b := path.Base(norm(p))
	return strings.TrimSuffix(b, path.Ext(b))
}

func parentDir(p string) string {
	d := path.Base(path.Dir(norm(p)))
	if d == "." || d == "/" {
		return ""
	}
	return d
}

// DiscoverName derives a stable service name for a process found listening on a port. Names come
// from what an operator would call the service: the jar, script, module or DLL, never a pid.
func DiscoverName(exe string, args []string, cwd string) string {
	base := strings.TrimSuffix(strings.ToLower(path.Base(norm(exe))), ".exe")
	first := func(skipFlags bool) string {
		for _, a := range args {
			if skipFlags && strings.HasPrefix(a, "-") {
				continue
			}
			return a
		}
		return ""
	}
	choose := func(n, dir string) string {
		n = cleanName(versionSuffix.ReplaceAllString(n, ""))
		if (n == "" || genericNames[strings.ToLower(n)]) && dir != "" {
			if d := cleanName(dir); d != "" {
				return d
			}
		}
		return n
	}
	switch {
	case base == "java":
		for i, a := range args {
			if a == "-jar" && i+1 < len(args) {
				return fallback(choose(stripExt(args[i+1]), parentDir(args[i+1])), base)
			}
		}
		for i := 0; i < len(args); i++ { // main class: first non-option, skipping the value of -cp/-classpath
			a := args[i]
			if a == "-cp" || a == "-classpath" || a == "--class-path" {
				i++
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			if strings.Contains(a, "catalina") || strings.HasPrefix(a, "org.apache.catalina") {
				return "tomcat"
			}
			parts := strings.Split(a, ".")
			return fallback(choose(parts[len(parts)-1], ""), base)
		}
	case base == "node" || base == "nodejs" || base == "deno" || base == "bun":
		if s := first(true); s != "" {
			return fallback(choose(stripExt(s), parentDir(s)), base)
		}
	case strings.HasPrefix(base, "python") || base == "gunicorn" || base == "uvicorn" || base == "celery" || base == "hypercorn" || base == "daphne":
		for i, a := range args {
			if a == "-m" && i+1 < len(args) {
				return fallback(choose(strings.Split(args[i+1], ".")[0], ""), base)
			}
		}
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if strings.Contains(a, ":") && !strings.Contains(a, "/") { // gunicorn app.wsgi:application
				return fallback(choose(strings.Split(strings.Split(a, ":")[0], ".")[0], ""), base)
			}
			return fallback(choose(stripExt(a), parentDir(a)), base)
		}
	case base == "dotnet":
		for _, a := range args {
			if strings.HasSuffix(strings.ToLower(a), ".dll") {
				return fallback(choose(stripExt(a), ""), base)
			}
		}
	}
	return fallback(cleanName(base), "unknown")
}

func fallback(name, def string) string {
	if name == "" {
		return cleanName(def)
	}
	return name
}
