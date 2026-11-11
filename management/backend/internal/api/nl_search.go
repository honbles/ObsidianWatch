package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

// P-14 / P-15: natural-language search.
//
// Safety rules (P-15) as implemented:
//   - the prompt carries only the query syntax and field names, never event
//     rows, hostnames, usernames or sample values;
//   - the model has no tools and no database access;
//   - its output is validated against an allowlist of prefixes and time
//     ranges, and is only RETURNED, never executed here: the UI shows it for
//     review/editing and the user runs it through the normal search endpoint
//     (parameterised, time-capped, statement timeout);
//   - the request is audited (actor, question, generated query) and rate
//     limited per user.

var nlAllowedPrefixes = map[string]bool{
	"host": true, "type": true, "event_type": true, "sev": true, "severity": true,
	"src": true, "src_ip": true, "dst": true, "dst_ip": true, "user": true,
	"proc": true, "process": true, "reg": true, "regkey": true, "file": true, "path": true,
	"cmd": true, "cmdline": true, "os": true, "source": true,
}

var nlAllowedSince = map[string]bool{"15m": true, "1h": true, "6h": true, "24h": true, "7d": true, "30d": true}

const nlPrompt = `You translate a security analyst's question into a search query for a SIEM event search box.
Query syntax: space-separated terms; "quoted phrases"; -term excludes; prefix filters
host: type: sev: src: dst: user: proc: reg: file: cmd: os: source: (e.g. proc:powershell.exe cmd:-enc).
Event types include process, network, logon, file, registry, dns.
Allowed time ranges: 15m, 1h, 6h, 24h, 7d, 30d.
Respond with JSON only: {"q":"<query>","since":"<time range>"}.
Use only the syntax above. Do not invent hostnames or usernames that the question does not state.

Question: `

// validateNLQuery checks model output against the allowlists and returns the
// cleaned query and time range.
func validateNLQuery(raw string) (q, since string, err error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	var out struct {
		Q     string `json:"q"`
		Since string `json:"since"`
	}
	if e := json.Unmarshal([]byte(strings.TrimSpace(raw)), &out); e != nil {
		return "", "", fmt.Errorf("model did not return valid JSON")
	}
	out.Q = strings.TrimSpace(out.Q)
	if out.Q == "" || len(out.Q) > 300 {
		return "", "", fmt.Errorf("generated query is empty or too long")
	}
	terms := splitSearchTerms(out.Q)
	if len(terms) > 12 {
		return "", "", fmt.Errorf("generated query has too many terms")
	}
	for _, t := range terms {
		t = strings.TrimPrefix(strings.TrimSpace(t), "-")
		if strings.HasPrefix(t, `"`) {
			continue
		}
		if i := strings.Index(t, ":"); i > 0 {
			if !nlAllowedPrefixes[strings.ToLower(t[:i])] {
				return "", "", fmt.Errorf("generated query uses unsupported filter %q", t[:i])
			}
		}
	}
	if !nlAllowedSince[out.Since] {
		out.Since = "24h"
	}
	return out.Q, out.Since, nil
}

var (
	nlMu   sync.Mutex
	nlHits = map[string][]time.Time{}
)

func nlAllow(user string) bool {
	nlMu.Lock()
	defer nlMu.Unlock()
	cut := time.Now().Add(-time.Minute)
	h := nlHits[user][:0]
	for _, t := range nlHits[user] {
		if t.After(cut) {
			h = append(h, t)
		}
	}
	if len(h) >= 10 {
		nlHits[user] = h
		return false
	}
	nlHits[user] = append(h, time.Now())
	return true
}

// nlSystemPrompt keeps a local model on task; hosted calls use callVulnAI's own system prompt.
// nlProvider is one way to turn the prompt into model text.
type nlProvider struct {
	Name  string
	Model string
	Call  func(ctx context.Context) (string, error)
}

var errAllNLProvidersFailed = errors.New("AI provider error: none of the configured providers could answer")

// runNLProviders tries each provider in order, giving each at most perCall.
// A provider that errors, or whose reply fails validateNLQuery, is skipped in
// favour of the next one. It returns the first valid query, the model that
// produced it, and a trail of "name:outcome" for the audit log. If every
// provider failed on transport/API errors it returns errAllNLProvidersFailed;
// if at least one replied but with an invalid query, the validation error of
// the last such reply is returned.
func runNLProviders(ctx context.Context, providers []nlProvider, perCall time.Duration) (q, since, model string, trail []string, err error) {
	var lastValidation error
	for _, p := range providers {
		if ctx.Err() != nil {
			break
		}
		cctx, cancel := context.WithTimeout(ctx, perCall)
		text, cerr := p.Call(cctx)
		cancel()
		if cerr != nil {
			trail = append(trail, p.Name+":error")
			continue
		}
		q, since, verr := validateNLQuery(text)
		if verr != nil {
			trail = append(trail, p.Name+":invalid")
			lastValidation = verr
			continue
		}
		trail = append(trail, p.Name+":ok")
		return q, since, p.Model, trail, nil
	}
	if lastValidation != nil {
		return "", "", "", trail, lastValidation
	}
	return "", "", "", trail, errAllNLProvidersFailed
}

const nlSystemPrompt = "You translate a security analyst's question into one event-search query. Respond with valid JSON only, no markdown and no explanation."

func handleNLSearch(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Question string `json:"question"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body")
			return
		}
		req.Question = strings.TrimSpace(req.Question)
		if req.Question == "" || len(req.Question) > 300 {
			writeJSONError(w, http.StatusBadRequest, "question must be 1-300 characters")
			return
		}
		actor := "unknown"
		if c := auth.GetClaims(r); c != nil && c.Username != "" {
			actor = c.Username
		}
		if !nlAllow(actor) {
			writeJSONError(w, http.StatusTooManyRequests, "too many requests, try again in a minute")
			return
		}
		groqKey, anthropicKey := cfg.Groq.APIKey, cfg.Anthropic.APIKey
		if s, err := db.GetSettingsPrefix(r.Context(), "ai"); err == nil {
			if v := s["groq_api_key"]; v != "" {
				groqKey = v
			}
			if v := s["anthropic_api_key"]; v != "" {
				anthropicKey = v
			}
		}
		prompt := nlPrompt + redactNLQuestion(req.Question)
		var providers []nlProvider
		// Order: a self-hosted model first (the question stays on the network),
		// then Groq, then Anthropic. If one fails or returns something that is
		// not a valid query, the next configured provider is tried.
		if local, ok := loadLocalLLM(r.Context(), db); ok {
			providers = append(providers, nlProvider{Name: "local", Model: local.Model,
				Call: func(ctx context.Context) (string, error) { return callLocalLLM(ctx, local, nlSystemPrompt, prompt) }})
		}
		if groqKey != "" {
			providers = append(providers, nlProvider{Name: "groq", Model: groqModelName(),
				Call: func(ctx context.Context) (string, error) {
					return callVulnAI(ctx, groqKey, groqModelName(), prompt)
				}})
		}
		if anthropicKey != "" {
			providers = append(providers, nlProvider{Name: "anthropic", Model: anthropicModelName(),
				Call: func(ctx context.Context) (string, error) {
					return callVulnAI(ctx, anthropicKey, anthropicModelName(), prompt)
				}})
		}
		if len(providers) == 0 {
			writeJSONError(w, http.StatusServiceUnavailable, "No AI provider configured. Add a key or a local model in Settings → AI.")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		q, since, model, attempts, verr := runNLProviders(ctx, providers, 20*time.Second)
		detail := "question=" + redactNLQuestion(req.Question) + " via=" + strings.Join(attempts, ",")
		if verr == nil {
			detail += " q=" + q + " since=" + since
		} else {
			detail += " rejected=" + verr.Error()
		}
		db.WriteAudit(r.Context(), actor, "nl_search", "/api/v1/events/nl-query", detail, clientIP(r))
		if verr != nil {
			status := http.StatusUnprocessableEntity
			if errors.Is(verr, errAllNLProvidersFailed) {
				status = http.StatusBadGateway
			}
			writeJSONError(w, status, verr.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"q": q, "since": since, "model": model})
	}
}

// P-15: the question is sent to a third-party model, so credential-shaped
// strings an analyst may have pasted are masked first. Hostnames, IPs and
// usernames are kept because they are what the search needs.
var nlSecretRes = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`(?i)\bsk-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`(?i)(password|passwd|secret|token|apikey|api_key)\s*[=:]\s*\S+`),
	regexp.MustCompile(`\b[A-Fa-f0-9]{40,}\b`),
}

func redactNLQuestion(q string) string {
	for _, re := range nlSecretRes {
		q = re.ReplaceAllString(q, "[redacted]")
	}
	return q
}
