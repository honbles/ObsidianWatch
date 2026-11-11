package api

import "testing"

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
