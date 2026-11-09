package store

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// testdata/issue_form_vectors.json is generated from src/store/issue-form.ts
// (normalizeRepoPresets / normalizeIssueForm / validateIssueFormSubmission)
// with Node, covering the JavaScript coercions (String(), trim, UTF-16 slice,
// truthiness) the Go port has to reproduce.
type issueFormVectors struct {
	Presets []struct {
		Name  string `json:"name"`
		Input any    `json:"input"`
		Want  any    `json:"want"`
	} `json:"presets"`
	Forms []struct {
		Name  string `json:"name"`
		Input any    `json:"input"`
		Want  any    `json:"want"`
	} `json:"forms"`
	Validate []struct {
		Name    string           `json:"name"`
		Form    IssueFormConfig  `json:"form"`
		Presets []TeamRepoPreset `json:"presets"`
		Values  map[string]any   `json:"values"`
		Want    any              `json:"want"`
	} `json:"validate"`
	Default any `json:"default"`
}

func loadIssueFormVectors(t *testing.T) issueFormVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/issue_form_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v issueFormVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

var generatedPresetID = regexp.MustCompile(`"repo_[0-9a-f]{12}"`)

func genericJSON(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	raw = generatedPresetID.ReplaceAll(raw, []byte(`"repo_<generated>"`))
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func validationShape(value IssueFormSubmission, failure *IssueFormError) any {
	if failure != nil {
		return map[string]any{"ok": false, "reason": failure.Reason, "field": failure.Field}
	}
	out := map[string]any{"title": value.Title, "body": value.Body}
	if value.Labels != nil {
		out["labels"] = value.Labels
	}
	if value.TargetRepoID != "" {
		out["targetRepoId"] = value.TargetRepoID
	}
	if value.TargetRepoLabel != "" {
		out["targetRepoLabel"] = value.TargetRepoLabel
	}
	if len(value.CustomFields) > 0 {
		custom := map[string]any{}
		for _, f := range value.CustomFields {
			custom[f.ID] = f.Value
		}
		out["customFields"] = custom
	}
	return map[string]any{"ok": true, "value": out}
}

func TestIssueFormMatchesTypeScriptVectors(t *testing.T) {
	t.Parallel()
	v := loadIssueFormVectors(t)
	if got, want := genericJSON(t, DefaultIssueForm()), genericJSON(t, v.Default); !reflect.DeepEqual(got, want) {
		t.Fatalf("default form\n got %#v\nwant %#v", got, want)
	}
	for _, tc := range v.Presets {
		got, want := genericJSON(t, NormalizeRepoPresets(tc.Input)), genericJSON(t, tc.Want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("presets %q\n got %#v\nwant %#v", tc.Name, got, want)
		}
	}
	for _, tc := range v.Forms {
		got, want := genericJSON(t, NormalizeIssueForm(tc.Input)), genericJSON(t, tc.Want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("form %q\n got %#v\nwant %#v", tc.Name, got, want)
		}
	}
	for _, tc := range v.Validate {
		value, failure := ValidateIssueFormSubmission(tc.Form, tc.Presets, tc.Values)
		got, want := genericJSON(t, validationShape(value, failure)), genericJSON(t, tc.Want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("validate %q\n got %#v\nwant %#v", tc.Name, got, want)
		}
	}
}

// Ports of test/issue-form.test.ts.

func findField(form IssueFormConfig, id string) *IssueFormField {
	for i := range form.Fields {
		if form.Fields[i].ID == id {
			return &form.Fields[i]
		}
	}
	return nil
}

func TestDefaultIssueFormRequiresTitleBodyRepo(t *testing.T) {
	t.Parallel()
	form := DefaultIssueForm()
	for _, id := range []string{"title", "body", "repo"} {
		if f := findField(form, id); f == nil || !f.IsRequired() {
			t.Fatalf("%s field = %+v", id, f)
		}
	}
	// Fresh copies: mutating one must not leak into the next.
	form.Fields[0].Label = "mutated"
	if DefaultIssueForm().Fields[0].Label != "标题" {
		t.Fatal("DefaultIssueForm returned a shared value")
	}
}

func TestValidateRejectsEmptyBodyAndRepoUnderDefaultForm(t *testing.T) {
	t.Parallel()
	form := DefaultIssueForm()
	presets := NormalizeRepoPresets([]any{map[string]any{"id": "repo_a", "label": "platform"}})
	if _, err := ValidateIssueFormSubmission(form, presets, map[string]any{"title": "fix bug", "body": "", "repo": map[string]any{"id": "repo_a"}}); err == nil || err.Reason != "body_required" {
		t.Fatalf("no body = %v", err)
	}
	if _, err := ValidateIssueFormSubmission(form, presets, map[string]any{"title": "fix bug", "body": "steps…"}); err == nil || err.Reason != "repo_required" {
		t.Fatalf("no repo = %v", err)
	}
}

func TestValidateAcceptsPresetRepoAndCustomFields(t *testing.T) {
	t.Parallel()
	fields := []any{}
	for _, f := range DefaultIssueForm().Fields {
		fields = append(fields, f)
	}
	fields = append(fields, map[string]any{"id": "priority", "type": "select", "label": "优先级", "required": true, "options": []any{"p0", "p1"}})
	form := NormalizeIssueForm(map[string]any{"fields": toGeneric(fields)})
	presets := NormalizeRepoPresets([]TeamRepoPreset{{ID: "repo_a", Label: "platform"}, {ID: "repo_b", Label: "botmux-clients", Remote: "org/botmux-clients"}})
	value, err := ValidateIssueFormSubmission(form, presets, map[string]any{
		"title": "看板太简单", "body": "卡片缺少仓库与描述", "repo": map[string]any{"id": "repo_b"}, "labels": "ux, p1", "priority": "p1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.TargetRepoID != "repo_b" || value.TargetRepoLabel != "botmux-clients" || strings.Join(value.Labels, ",") != "ux,p1" {
		t.Fatalf("value = %+v", value)
	}
	if len(value.CustomFields) != 1 || value.CustomFields[0].ID != "priority" || value.CustomFields[0].Value != "p1" {
		t.Fatalf("custom = %+v", value.CustomFields)
	}
}

func TestValidateAllowsCustomRepoLabel(t *testing.T) {
	t.Parallel()
	value, err := ValidateIssueFormSubmission(DefaultIssueForm(), nil, map[string]any{"title": "x", "body": "y", "repo": map[string]any{"label": "my-local-fork"}})
	if err != nil || value.TargetRepoLabel != "my-local-fork" || value.TargetRepoID != "" {
		t.Fatalf("value = %+v err = %v", value, err)
	}
}

func TestNormalizeIssueFormKeepsTitleRequiredAndDropsEmptySelect(t *testing.T) {
	t.Parallel()
	form := NormalizeIssueForm(map[string]any{"fields": []any{map[string]any{"id": "body", "type": "textarea", "label": "描述", "required": true}}})
	if f := findField(form, "title"); f == nil || !f.IsRequired() || form.Fields[0].ID != "title" {
		t.Fatalf("form = %+v", form)
	}
	form = NormalizeIssueForm(map[string]any{"fields": []any{
		map[string]any{"id": "title", "type": "text", "label": "标题", "required": true},
		map[string]any{"id": "priority", "type": "select", "label": "优先级", "options": []any{}},
		map[string]any{"id": "sev", "type": "select", "label": "严重度", "options": []any{"s1", "s2"}},
	}})
	if findField(form, "priority") != nil || findField(form, "sev") == nil {
		t.Fatalf("form = %+v", form)
	}
}

func TestValidateRejectsSelectValueNotInOptions(t *testing.T) {
	t.Parallel()
	form := NormalizeIssueForm(map[string]any{"fields": []any{
		map[string]any{"id": "title", "type": "text", "label": "标题", "required": true},
		map[string]any{"id": "body", "type": "textarea", "label": "描述", "required": true},
		map[string]any{"id": "repo", "type": "repo", "label": "仓库", "required": true, "allowCustom": true},
		map[string]any{"id": "priority", "type": "select", "label": "优先级", "required": true, "options": []any{"p0", "p1"}},
	}})
	_, err := ValidateIssueFormSubmission(form, nil, map[string]any{"title": "t", "body": "b", "repo": map[string]any{"label": "x"}, "priority": "p9"})
	if err == nil || err.Reason != "invalid_option" || err.Field != "priority" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveTeamIssueSettingsDefaults(t *testing.T) {
	t.Parallel()
	presets, form := ResolveTeamIssueSettings(TeamDoc{})
	if presets == nil || len(presets) != 0 || !reflect.DeepEqual(form, DefaultIssueForm()) {
		t.Fatalf("defaults = %#v %#v", presets, form)
	}
	stored := IssueFormConfig{Fields: []IssueFormField{{ID: "title", Type: "text", Label: "T"}}}
	presets, form = ResolveTeamIssueSettings(TeamDoc{RepoPresets: []TeamRepoPreset{{ID: "r", Label: "L"}}, IssueForm: &stored})
	if len(presets) != 1 || presets[0].ID != "r" || len(form.Fields) != 1 || !form.Fields[0].IsRequired() {
		t.Fatalf("resolved = %#v %#v", presets, form)
	}
	if stored.Fields[0].Required != nil {
		t.Fatal("resolve mutated the stored form")
	}
}

func TestJSNumberString(t *testing.T) {
	t.Parallel()
	cases := map[float64]string{0: "0", 1: "1", -1.5: "-1.5", 0.1: "0.1", 1e21: "1e+21", 1e20: "100000000000000000000",
		1e-7: "1e-7", 1.5e-7: "1.5e-7", 0.000001: "0.000001", 5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308",
		123.456: "123.456", 1.0 / 3: "0.3333333333333333"}
	for in, want := range cases {
		if got := jsNumberString(in); got != want {
			t.Errorf("jsNumberString(%v) = %q, want %q", in, got, want)
		}
	}
}
