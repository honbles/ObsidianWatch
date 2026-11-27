package api

import "strings"

// Findings in test, fixture and example code are usually not reachable in production: in OWASP Juice Shop about a
// third of the built-in findings were in tests, specs, fixtures and sample snippets. They are kept (test code is
// still code, and a bad pattern there gets copied) but marked test_code and lowered one severity level, so they
// sort below production findings and block a pull request only at a lower threshold. Not lowered: secrets (a real
// credential in a test file is still a real credential) and dependency findings.

var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true, "e2e": true, "cypress": true,
	"testdata": true, "test-data": true, "testing": true, "fixtures": true, "fixture": true, "mocks": true,
	"__mocks__": true, "examples": true, "example": true, "samples": true, "sample": true, "demo": true,
	"benchmarks": true, "integration-tests": true, "unit-tests": true,
}

// isTestPath reports a file that is test, fixture or example code, by directory or by file-name convention.
func isTestPath(file string) bool {
	l := strings.ToLower(file)
	segs := strings.Split(l, "/")
	for _, s := range segs[:len(segs)-1] {
		if testDirs[s] {
			return true
		}
	}
	base := segs[len(segs)-1]
	for _, suf := range []string{"_test.go", "_test.py", "_spec.rb", "_test.rb", "test.java", "tests.java", "test.kt",
		"tests.cs", "test.cs", "_test.dart", "_test.exs"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	if strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py") || base == "conftest.py" {
		return true
	}
	for _, mid := range []string{".test.", ".spec.", ".e2e.", ".cy.", ".stories."} {
		if strings.Contains(base, mid) {
			return true
		}
	}
	return false
}

var lowerSeverity = map[string]string{"critical": "high", "high": "medium", "medium": "low", "low": "low", "info": "info"}

// markTestCode marks and lowers findings in test code, once (TestCode guards a second pass).
func markTestCode(fs []SASTFinding) {
	for i := range fs {
		f := &fs[i]
		if f.TestCode || f.Package != "" || isCredentialFinding(*f) || !isTestPath(f.File) {
			continue
		}
		f.TestCode = true
		if s, ok := lowerSeverity[f.Severity]; ok {
			f.Severity = s
		}
	}
}
