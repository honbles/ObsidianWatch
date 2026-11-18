//go:build !windows

package otel

// eventOS lets the package build and its tests run on other hosts (CI, Linux dev machines).
const eventOS = "windows"
