package config

// EmbeddedConfig holds the probe.yaml baked in at compile time by the Agent Builder.
// Empty in development builds — falls back to reading probe.yaml from disk.
// DO NOT EDIT — overwritten by Agent Builder before each compile.
var EmbeddedConfig = ""
