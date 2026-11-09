package api

import (
	"context"
	"time"

	"obsidianwatch/management/internal/store"
)

// SA-07: SAST / code-scan AI analysis sends findings about customer source
// code to a hosted LLM. These helpers bound what leaves the server:
//   - source snippets are only included when the operator opts in
//     (setting ai.send_source_snippets = "true"); otherwise findings are sent
//     as metadata only (rule, severity, file, line);
//   - the number of findings and snippet length are capped;
//   - the findings block is fenced as untrusted (repo content is attacker
//     influenced → prompt injection) and the injection guard is prepended;
//   - requests are rate-limited.
const (
	aiMaxFindings    = 150
	aiMaxSnippetRune = 300
)

var sourceAILimiter = NewRateLimiter(10*time.Minute, 6)

func aiSourceSnippetsAllowed(ctx context.Context, db *store.DB) bool {
	v, err := db.GetSetting(ctx, "ai.send_source_snippets")
	return err == nil && v == "true"
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
