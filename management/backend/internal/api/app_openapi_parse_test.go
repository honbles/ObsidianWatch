package api

import (
	"strings"
	"testing"
)

const appTestOAS3 = `
openapi: 3.0.1
info: {title: Shop, version: "2.1"}
servers: [{url: "https://shop.example/api"}]
paths:
  /Users:
    post:
      summary: register
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/User'}
  /Products/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: integer}}
    get:
      parameters:
        - {$ref: '#/components/parameters/Lang'}
        - {name: q, in: query, schema: {type: string}}
        - {name: session, in: cookie, schema: {type: string}}
        - {name: X-Trace, in: header, schema: {type: string}}
components:
  parameters:
    Lang: {name: lang, in: query, schema: {type: string}}
  schemas:
    User:
      allOf:
        - {$ref: '#/components/schemas/Base'}
        - type: object
          properties:
            email: {type: string}
            password: {type: string}
            securityQuestion:
              type: object
              properties: {id: {type: integer}}
            items:
              type: array
              items: {type: object, properties: {sku: {type: string}}}
            parent: {$ref: '#/components/schemas/User'}
    Base:
      type: object
      properties: {id: {type: integer}}
`

func appFieldSet(r appDeclaredRoute) map[string]string {
	m := map[string]string{}
	for _, f := range r.Fields {
		m[f.Name] = f.Location
	}
	return m
}

func TestParseOpenAPI3YAML(t *testing.T) {
	api, err := appParseOpenAPI([]byte(appTestOAS3), "")
	if err != nil {
		t.Fatal(err)
	}
	if api.Title != "Shop" || api.Version != "2.1" || len(api.Routes) != 2 {
		t.Fatalf("api: %+v", api)
	}
	byKey := map[string]appDeclaredRoute{}
	for _, r := range api.Routes {
		byKey[r.Method+" "+r.Route] = r
	}
	u, ok := byKey["POST /api/Users"]
	if !ok {
		t.Fatalf("server path prefix missing: %+v", api.Routes)
	}
	f := appFieldSet(u)
	for _, want := range []string{"id", "email", "password", "securityQuestion.id", "items[].sku"} {
		if f[want] != "body" {
			t.Errorf("missing body field %s in %v", want, f)
		}
	}
	g := appFieldSet(byKey["GET /api/Products/{id}"])
	if g["id"] != "path" || g["lang"] != "query" || g["q"] != "query" || g["X-Trace"] != "header" {
		t.Errorf("params: %v", g)
	}
	if _, has := g["session"]; has {
		t.Error("cookie parameters must be skipped")
	}
	// a recursive schema terminates
	if len(u.Fields) > appSpecMaxFields {
		t.Error("cap")
	}
}

func TestParseSwagger2JSONAndBasePath(t *testing.T) {
	doc := `{"swagger":"2.0","basePath":"/v1","info":{"title":"Old","version":"1"},"paths":{
	 "/login":{"post":{"parameters":[
	   {"name":"body","in":"body","schema":{"$ref":"#/definitions/Cred"}},
	   {"name":"remember","in":"formData","type":"boolean"}]}}},
	 "definitions":{"Cred":{"properties":{"email":{"type":"string"},"password":{"type":"string"}}}}}`
	api, err := appParseOpenAPI([]byte(doc), "")
	if err != nil || len(api.Routes) != 1 {
		t.Fatalf("%v %+v", err, api)
	}
	r := api.Routes[0]
	f := appFieldSet(r)
	if r.Route != "/v1/login" || f["email"] != "body" || f["remember"] != "body" {
		t.Errorf("%+v", r)
	}
	api, _ = appParseOpenAPI([]byte(doc), "/gateway/")
	if api.Routes[0].Route != "/gateway/login" {
		t.Errorf("base path override: %s", api.Routes[0].Route)
	}
}

func TestParseOpenAPIRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":       "",
		"not a spec":  `{"hello":"world"}`,
		"bad json":    `{"openapi":`,
		"no ops":      `{"openapi":"3.0.0","paths":{"/a":{}}}`,
		"yaml scalar": `just text`,
	} {
		if _, err := appParseOpenAPI([]byte(doc), ""); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
	if _, err := appParseOpenAPI([]byte(strings.Repeat("a", appSpecMaxBytes+1)), ""); err == nil {
		t.Error("oversize")
	}
}

func TestRouteShape(t *testing.T) {
	a, b, c := appRouteShape("/Users/{id}/orders"), appRouteShape("/users/:uid/orders"), appRouteShape("/users/<int:n>/orders")
	if a != b || b != c || appRouteShape("/users/x") == a {
		t.Fatalf("%s %s %s", a, b, c)
	}
}
