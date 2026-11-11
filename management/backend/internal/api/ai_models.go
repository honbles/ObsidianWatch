package api

// AI model names. Providers retire models without notice (Groq retired
// llama-3.3-70b-versatile and every AI call then failed), so the names are
// settings an admin can change, not constants buried in nine handlers.

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"obsidianwatch/management/internal/store"
)

const (
	defaultGroqModel      = "openai/gpt-oss-120b"
	defaultAnthropicModel = "claude-sonnet-5-5"
	settingGroqModel      = "ai.groq_model"
	settingAnthropicModel = "ai.anthropic_model"
)

var (
	aiModelMu        sync.RWMutex
	curGroqModel     = defaultGroqModel
	curAnthropicName = defaultAnthropicModel
	modelNameRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,99}$`)
)

func groqModelName() string {
	aiModelMu.RLock()
	defer aiModelMu.RUnlock()
	return curGroqModel
}

func anthropicModelName() string {
	aiModelMu.RLock()
	defer aiModelMu.RUnlock()
	return curAnthropicName
}

func validModelName(s string) bool { return modelNameRe.MatchString(s) }

// setAIModels updates the in-memory names; empty or invalid values restore the defaults.
func setAIModels(groq, anthropic string) {
	groq, anthropic = strings.TrimSpace(groq), strings.TrimSpace(anthropic)
	aiModelMu.Lock()
	defer aiModelMu.Unlock()
	curGroqModel, curAnthropicName = defaultGroqModel, defaultAnthropicModel
	if validModelName(groq) {
		curGroqModel = groq
	}
	if validModelName(anthropic) {
		curAnthropicName = anthropic
	}
}

// refreshAIModels loads the configured names from the settings table.
func refreshAIModels(ctx context.Context, db *store.DB) {
	g, _ := db.GetSetting(ctx, settingGroqModel)
	a, _ := db.GetSetting(ctx, settingAnthropicModel)
	setAIModels(g, a)
}

// isAnthropicModel reports whether a model name belongs to Anthropic.
func isAnthropicModel(m string) bool { return strings.HasPrefix(m, "claude") }
