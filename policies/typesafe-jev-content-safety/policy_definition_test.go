/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package typesafejevcontentsafety

import (
	"os"
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

type policyDefinitionFile struct {
	Parameters map[string]interface{} `yaml:"parameters"`
	UI         struct {
		FormSchema map[string]interface{} `yaml:"formSchema"`
	} `yaml:"x-wso2-policy-ui"`
}

func readPolicyDefinition(t *testing.T) policyDefinitionFile {
	t.Helper()
	raw, err := os.ReadFile("policy-definition.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var def policyDefinitionFile
	if err := yaml.Unmarshal(raw, &def); err != nil {
		t.Fatalf("policy-definition.yaml is not valid YAML: %v", err)
	}
	return def
}

// The AI Workspace renders the form from x-wso2-policy-ui.formSchema and saves
// what the form produces, but the gateway validates params against `parameters`
// only. So the two must describe the same data: the same fields, types, enums
// and defaults, and the form must require at least what `parameters` requires.
func TestFormSchemaMatchesParameters(t *testing.T) {
	def := readPolicyDefinition(t)
	if def.UI.FormSchema == nil {
		t.Fatal("policy-definition.yaml has no x-wso2-policy-ui.formSchema")
	}
	compareSchemas(t, "parameters", def.Parameters, def.UI.FormSchema)
}

func compareSchemas(t *testing.T, path string, params, form map[string]interface{}) {
	t.Helper()
	for _, key := range []string{"type", "enum"} {
		p, inParams := params[key]
		if f, inForm := form[key]; inParams != inForm || !reflect.DeepEqual(p, f) {
			t.Errorf("%s: %s is %v in parameters but %v in formSchema", path, key, p, f)
		}
	}
	if p, ok := params["default"]; ok {
		if f, ok := form["default"]; ok && !reflect.DeepEqual(p, f) {
			t.Errorf("%s: default differs between parameters and formSchema", path)
		}
	}
	formRequired := stringSet(form["required"])
	for r := range stringSet(params["required"]) {
		if !formRequired[r] {
			t.Errorf("%s: %q is required in parameters but not in formSchema", path, r)
		}
	}

	paramProps, formProps := properties(t, path, params), properties(t, path, form)
	for _, name := range sortedKeys(paramProps) {
		f, ok := formProps[name]
		if !ok {
			t.Errorf("%s.%s: missing from formSchema", path, name)
			continue
		}
		compareSchemas(t, path+"."+name, paramProps[name], f)
	}
	for _, name := range sortedKeys(formProps) {
		if _, ok := paramProps[name]; !ok {
			t.Errorf("%s.%s: in formSchema but not in parameters", path, name)
		}
	}

	paramItems, _ := params["items"].(map[string]interface{})
	formItems, _ := form["items"].(map[string]interface{})
	switch {
	case paramItems != nil && formItems != nil:
		compareSchemas(t, path+"[]", paramItems, formItems)
	case paramItems != nil || formItems != nil:
		t.Errorf("%s: items is set in only one of parameters and formSchema", path)
	}
}

// properties returns an object schema's properties, including the ones that
// if/then/else branches add (directly or under allOf), merged by name. A field
// a branch declares again must keep its type.
func properties(t *testing.T, path string, schema map[string]interface{}) map[string]map[string]interface{} {
	t.Helper()
	out := map[string]map[string]interface{}{}
	var collect func(s map[string]interface{})
	collect = func(s map[string]interface{}) {
		props, _ := s["properties"].(map[string]interface{})
		for name, v := range props {
			fragment, _ := v.(map[string]interface{})
			merged, seen := out[name]
			if !seen {
				merged = map[string]interface{}{}
				out[name] = merged
			}
			if seen && fragment["type"] != nil && merged["type"] != nil && !reflect.DeepEqual(fragment["type"], merged["type"]) {
				t.Errorf("%s.%s: a condition changes the type from %v to %v", path, name, merged["type"], fragment["type"])
			}
			for k, fv := range fragment {
				if _, set := merged[k]; !set {
					merged[k] = fv
				}
			}
		}
		for _, branch := range []string{"then", "else"} {
			if b, ok := s[branch].(map[string]interface{}); ok {
				collect(b)
			}
		}
		all, _ := s["allOf"].([]interface{})
		for _, a := range all {
			if m, ok := a.(map[string]interface{}); ok {
				collect(m)
			}
		}
	}
	collect(schema)
	return out
}

func stringSet(v interface{}) map[string]bool {
	set := map[string]bool{}
	list, _ := v.([]interface{})
	for _, item := range list {
		if s, ok := item.(string); ok {
			set[s] = true
		}
	}
	return set
}

func sortedKeys(m map[string]map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
