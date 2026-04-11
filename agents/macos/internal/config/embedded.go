package config

// EmbeddedConfig holds the agent.yaml content baked in at compile time by the
// Agent Builder. When non-empty, config.LoadEmbedded() uses this instead of
// reading a file from disk — making the binary fully self-contained.
//
// In normal development builds this is empty and LoadEmbedded() falls back to
// reading agent.yaml from disk as usual.
//
// DO NOT EDIT — this file is overwritten by the Agent Builder before each
// platform compile and restored to empty afterwards.
var EmbeddedConfig = ""
