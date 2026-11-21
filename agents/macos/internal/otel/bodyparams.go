package otel

// bodyparams.go - request-body fields reported by the language helper in the span attribute
// "ow.request.body": a JSON object of field name to scalar value, nested names joined with dots. Like query
// strings they are read only to learn field names and, for reviewed routes, to forward allowed values. The
// attribute itself is never stored or forwarded.

import (
	"encoding/json"
	"strconv"
)

const (
	bodyAttr        = "ow.request.body"
	maxBodyAttrLen  = 32 * 1024
	maxBodyDepth    = 4
	maxBodyElements = 200
)

// bodyParams flattens the helper's JSON into names and capped string values. Anything that is not a JSON
// object, or is oversized, yields nothing.
func bodyParams(raw string) ([]string, map[string]string) {
	if raw == "" || len(raw) > maxBodyAttrLen {
		return nil, nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return nil, nil
	}
	var names []string
	vals := map[string]string{}
	count := 0
	var walk func(prefix string, v any, depth int)
	walk = func(prefix string, v any, depth int) {
		if count >= maxBodyElements || len(names) >= maxParamsPerSpan {
			return
		}
		count++
		switch t := v.(type) {
		case map[string]any:
			if depth >= maxBodyDepth {
				return
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sortStrings(keys)
			for _, k := range keys {
				n := k
				if prefix != "" {
					n = prefix + "." + k
				}
				walk(n, t[k], depth+1)
			}
		case []any:
			if depth >= maxBodyDepth || len(t) == 0 {
				return
			}
			walk(prefix+"[]", t[0], depth+1) // an array contributes the shape of its first element
		default:
			if prefix == "" || !validParamName(prefix) {
				return
			}
			if _, dup := vals[prefix]; dup {
				return
			}
			s := ""
			switch x := t.(type) {
			case string:
				s = x
			case float64:
				s = strconv.FormatFloat(x, 'f', -1, 64)
			case bool:
				s = strconv.FormatBool(x)
			case nil:
				s = ""
			}
			if len(s) > maxParamValueLen {
				s = s[:maxParamValueLen]
			}
			vals[prefix] = s
			names = append(names, prefix)
		}
	}
	walk("", root, 0)
	return names, vals
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func (s *Span) addBody(raw string) {
	names, vals := bodyParams(raw)
	s.ParamNames = mergeParamNames(s.ParamNames, names)
	if len(vals) > 0 && s.ParamValues == nil {
		s.ParamValues = map[string]string{}
	}
	for k, v := range vals {
		if _, ok := s.ParamValues[k]; !ok {
			s.ParamValues[k] = v
		}
	}
}
