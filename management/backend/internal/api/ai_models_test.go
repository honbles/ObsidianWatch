package api

import (
	"strings"
	"testing"
)

func TestAIModelNames(t *testing.T) {
	t.Cleanup(func() { setAIModels("", "") })
	if groqModelName() != defaultGroqModel || anthropicModelName() != defaultAnthropicModel {
		t.Fatal("defaults expected")
	}
	setAIModels("openai/gpt-oss-20b", "claude-haiku-5-5")
	if groqModelName() != "openai/gpt-oss-20b" || anthropicModelName() != "claude-haiku-5-5" {
		t.Errorf("custom names not applied: %s %s", groqModelName(), anthropicModelName())
	}
	setAIModels("bad name; rm -rf", "")
	if groqModelName() != defaultGroqModel {
		t.Error("invalid names must fall back to the default")
	}
	if !isAnthropicModel("claude-sonnet-5-5") || isAnthropicModel("openai/gpt-oss-120b") {
		t.Error("provider detection wrong")
	}
}

func TestGroqTuneAndExtract(t *testing.T) {
	b := map[string]interface{}{}
	groqTune(b, "openai/gpt-oss-120b", 1000)
	if b["reasoning_effort"] != "low" || b["max_completion_tokens"].(int) <= 1000 || b["max_tokens"] != nil {
		t.Fatalf("gpt-oss tuning wrong: %v", b)
	}
	b = map[string]interface{}{}
	groqTune(b, "llama-x", 500)
	if b["max_tokens"] != 500 {
		t.Fatalf("plain tuning wrong: %v", b)
	}
	if got := extractJSONObject("sure:\n```json\n{\"a\":1}\n```"); got != `{"a":1}` {
		t.Fatalf("extract: %q", got)
	}
}

func TestHumanizeAIAnswer(t *testing.T) {
	if got := humanizeAIAnswer("plain text"); got != "plain text" {
		t.Fatalf("plain changed: %q", got)
	}
	got := humanizeAIAnswer("```json\n{\"verdict\":\"benign\",\"steps\":[\"a\",\"b\"]}\n```")
	if !strings.Contains(got, "verdict: benign") || !strings.Contains(got, "• a") {
		t.Fatalf("humanize: %q", got)
	}
}
