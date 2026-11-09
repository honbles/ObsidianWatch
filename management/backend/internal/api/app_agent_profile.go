package api

// app_agent_profile.go — OWNED BY THE APPLICATION BUILD. Returns the extra
// top-level YAML (e.g. "app_monitoring:") appended to endpoint agent configs.
// Must return "" when cfg.EnableAppProfile is false. Foundation stub.

func appProfileYAML(cfg AgentBuilderConfig) string {
	_ = cfg
	return ""
}
