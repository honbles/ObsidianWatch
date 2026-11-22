package api

// app_openapi_parse.go - reads an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML) into the routes and field
// names it declares. Only NAMES are taken: path, query and header parameters, and the properties of request-body
// schemas with nested names joined by dots ("securityQuestion.id") and arrays marked "[]" ("items[].sku"), the
// same shapes the agent reports. Cookie parameters are skipped. No example or default value is read.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	appSpecMaxBytes      = 5 << 20
	appSpecMaxRoutes     = 500 // the same per-service route limit the ingest applies
	appSpecMaxFields     = 100 // names kept per route
	appSpecMaxSchemaDeep = 4   // the depth the agent flattens bodies to
)

type appDeclaredField struct {
	Name     string `json:"name"`
	Location string `json:"location"` // query | path | header | body
}

type appDeclaredRoute struct {
	Route   string             `json:"route"`
	Method  string             `json:"method"`
	Summary string             `json:"summary,omitempty"`
	Fields  []appDeclaredField `json:"fields"`
}

type appDeclaredAPI struct {
	Title   string             `json:"title"`
	Version string             `json:"version"`
	Routes  []appDeclaredRoute `json:"routes"`
	Skipped int                `json:"skipped"` // routes over the limit
}

var appSpecMethods = []string{"get", "put", "post", "delete", "patch", "options", "head"}

// appParseOpenAPI parses spec text. basePath, when not empty, replaces the server or basePath found in the document.
func appParseOpenAPI(raw []byte, basePath string) (*appDeclaredAPI, error) {
	if len(raw) == 0 {
		return nil, errors.New("the document is empty")
	}
	if len(raw) > appSpecMaxBytes {
		return nil, errors.New("the document is larger than 5 MB")
	}
	var doc map[string]any
	if t := strings.TrimSpace(string(raw[:min(len(raw), 64)])); strings.HasPrefix(t, "{") {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("not valid JSON: %v", err)
		}
	} else {
		var y any
		if err := yaml.Unmarshal(raw, &y); err != nil {
			return nil, fmt.Errorf("not valid YAML or JSON: %v", err)
		}
		m, ok := appNorm(y).(map[string]any)
		if !ok {
			return nil, errors.New("the document is not an object")
		}
		doc = m
	}
	paths, _ := doc["paths"].(map[string]any)
	if paths == nil || (doc["openapi"] == nil && doc["swagger"] == nil) {
		return nil, errors.New("this does not look like an OpenAPI or Swagger document (no openapi/swagger version and no paths)")
	}
	api := &appDeclaredAPI{}
	if info, ok := doc["info"].(map[string]any); ok {
		api.Title, api.Version = appStr(info["title"], 120), appStr(info["version"], 60)
	}
	prefix := appSpecBase(doc)
	if bp := strings.TrimSpace(basePath); bp != "" {
		prefix = bp
	}
	prefix = "/" + strings.Trim(prefix, "/")
	if prefix == "/" {
		prefix = ""
	}

	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, p := range keys {
		item, _ := paths[p].(map[string]any)
		if item == nil || !strings.HasPrefix(p, "/") {
			continue
		}
		item = appResolve(doc, item, 0)
		for _, m := range appSpecMethods {
			op, _ := item[m].(map[string]any)
			if op == nil {
				continue
			}
			op = appResolve(doc, op, 0)
			if len(api.Routes) >= appSpecMaxRoutes {
				api.Skipped++
				continue
			}
			r := appDeclaredRoute{Route: appCleanPath(prefix + p), Method: strings.ToUpper(m), Summary: appStr(op["summary"], 200)}
			seen := map[string]bool{}
			add := func(name, loc string) {
				if name == "" || !appPayloadNameOK(name) || seen[name] || len(r.Fields) >= appSpecMaxFields {
					return
				}
				seen[name] = true
				r.Fields = append(r.Fields, appDeclaredField{Name: name, Location: loc})
			}
			// parameters: the path item's, then the operation's (an operation overrides by name and location)
			var params []any
			params = append(params, appList(item["parameters"])...)
			params = append(params, appList(op["parameters"])...)
			for _, pr := range params {
				pm := appResolve(doc, pr, 0)
				if pm == nil {
					continue
				}
				name, in := appStr(pm["name"], 80), appStr(pm["in"], 12)
				switch in {
				case "query", "path", "header":
					add(name, in)
				case "formData": // Swagger 2
					add(name, "body")
				case "body": // Swagger 2: the schema is the body
					appSchemaNames(doc, pm["schema"], "", 0, map[string]bool{}, func(n string) { add(n, "body") })
				}
			}
			if rb := appResolve(doc, op["requestBody"], 0); rb != nil {
				content, _ := rb["content"].(map[string]any)
				for _, ct := range appPreferred(content) {
					mt, _ := content[ct].(map[string]any)
					if mt != nil {
						appSchemaNames(doc, mt["schema"], "", 0, map[string]bool{}, func(n string) { add(n, "body") })
					}
				}
			}
			api.Routes = append(api.Routes, r)
		}
	}
	if len(api.Routes) == 0 {
		return nil, errors.New("the document declares no operations")
	}
	return api, nil
}

// appPreferred orders a requestBody's media types: JSON first, then forms, then anything else, so the names
// of the most likely body come first when the per-route cap bites.
func appPreferred(content map[string]any) []string {
	var json, form, other []string
	for ct := range content {
		l := strings.ToLower(ct)
		switch {
		case strings.Contains(l, "json"):
			json = append(json, ct)
		case strings.Contains(l, "form"):
			form = append(form, ct)
		default:
			other = append(other, ct)
		}
	}
	sort.Strings(json)
	sort.Strings(form)
	sort.Strings(other)
	return append(append(json, form...), other...)
}

// appSchemaNames walks a schema and reports the leaf and container field names it declares.
func appSchemaNames(doc map[string]any, schema any, prefix string, depth int, visiting map[string]bool, emit func(string)) {
	sm, _ := schema.(map[string]any)
	if sm == nil || depth > appSpecMaxSchemaDeep {
		return
	}
	if ref, ok := sm["$ref"].(string); ok {
		if visiting[ref] {
			return // recursive schema
		}
		visiting[ref] = true
		defer delete(visiting, ref)
		r, _ := appLookupRef(doc, ref).(map[string]any)
		appSchemaNames(doc, r, prefix, depth, visiting, emit)
		return
	}
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		for _, sub := range appList(sm[k]) {
			appSchemaNames(doc, sub, prefix, depth, visiting, emit)
		}
	}
	if items, ok := sm["items"]; ok {
		appSchemaNames(doc, items, prefix+"[]", depth+1, visiting, emit)
	}
	props, _ := sm["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for n := range props {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		full := n
		if prefix != "" {
			full = prefix + "." + n
		}
		sub, _ := props[n].(map[string]any)
		if appSchemaHasChildren(doc, sub) && depth+1 <= appSpecMaxSchemaDeep {
			appSchemaNames(doc, sub, full, depth+1, visiting, emit)
			continue
		}
		emit(full)
	}
}

// appSchemaHasChildren reports whether a property is an object or array with declared structure.
func appSchemaHasChildren(doc map[string]any, s map[string]any) bool {
	if s == nil {
		return false
	}
	if ref, ok := s["$ref"].(string); ok {
		r, _ := appLookupRef(doc, ref).(map[string]any)
		return appSchemaHasChildren(doc, r)
	}
	if p, ok := s["properties"].(map[string]any); ok && len(p) > 0 {
		return true
	}
	if _, ok := s["items"]; ok {
		return true
	}
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		if len(appList(s[k])) > 0 {
			return true
		}
	}
	return false
}

// appResolve follows a "$ref" (one level, repeated up to 8 times) and returns the referenced object.
func appResolve(doc map[string]any, v any, _ int) map[string]any {
	m, _ := v.(map[string]any)
	for i := 0; m != nil && i < 8; i++ {
		ref, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		m, _ = appLookupRef(doc, ref).(map[string]any)
	}
	return m
}

// appLookupRef resolves a local reference such as "#/components/schemas/User". External references are not followed.
func appLookupRef(doc map[string]any, ref string) any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var cur any = doc
	for _, part := range strings.Split(ref[2:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

func appSpecBase(doc map[string]any) string {
	if bp, ok := doc["basePath"].(string); ok { // Swagger 2
		return bp
	}
	servers := appList(doc["servers"])
	if len(servers) == 0 {
		return ""
	}
	sm, _ := servers[0].(map[string]any)
	u := appStr(sm["url"], 300)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
		if j := strings.IndexByte(u, '/'); j >= 0 {
			u = u[j:]
		} else {
			u = ""
		}
	}
	if strings.Contains(u, "{") { // a server variable: the path cannot be known
		return ""
	}
	return u
}

func appCleanPath(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	if len(p) > 256 {
		p = p[:256]
	}
	return p
}

func appList(v any) []any { l, _ := v.([]any); return l }

func appStr(v any, max int) string {
	s, _ := v.(string)
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// appNorm turns yaml.v3's decoded maps (which may be map[any]any) into map[string]any all the way down.
func appNorm(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = appNorm(x)
		}
		return t
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[fmt.Sprint(k)] = appNorm(x)
		}
		return out
	case []any:
		for i, x := range t {
			t[i] = appNorm(x)
		}
		return t
	}
	return v
}

// appRouteShape reduces a route template to its shape so "/users/{id}", "/users/:id" and "/users/<int:uid>" compare equal.
func appRouteShape(route string) string {
	parts := strings.Split(route, "/")
	for i, p := range parts {
		if (strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}")) || strings.HasPrefix(p, ":") || (strings.HasPrefix(p, "<") && strings.HasSuffix(p, ">")) {
			parts[i] = "{}"
		}
	}
	return strings.ToLower(strings.Join(parts, "/"))
}
