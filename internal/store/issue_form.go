package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

// Team Issue Board settings: preset repositories and the customizable create
// form. System field ids are fixed (title/body/repo/labels); any other field
// is custom and its value lands in the issue's customFields.

// TeamRepoPreset is one preset repository offered by the create form.
type TeamRepoPreset struct {
	ID    string `json:"id" bson:"id"`
	Label string `json:"label" bson:"label"`
	// Remote is an optional git remote / owner/repo hint (display only; never
	// a machine-local path).
	Remote string `json:"remote,omitempty" bson:"remote,omitempty"`
}

// Issue form field types.
const (
	IssueFieldText        = "text"
	IssueFieldTextarea    = "textarea"
	IssueFieldSelect      = "select"
	IssueFieldMultiselect = "multiselect"
	IssueFieldRepo        = "repo"
)

// IssueFormField is one create-form field. Required and AllowCustom are
// pointers because the TS shape distinguishes an absent key from an explicit
// false (the default labels field carries "required": false).
type IssueFormField struct {
	ID          string   `json:"id" bson:"id"`
	Type        string   `json:"type" bson:"type"`
	Label       string   `json:"label" bson:"label"`
	Required    *bool    `json:"required,omitempty" bson:"required,omitempty"`
	Placeholder string   `json:"placeholder,omitempty" bson:"placeholder,omitempty"`
	Options     []string `json:"options,omitempty" bson:"options,omitempty"`
	// AllowCustom applies to type=repo: whether free text outside the presets
	// is accepted.
	AllowCustom *bool `json:"allowCustom,omitempty" bson:"allowCustom,omitempty"`
}

// IsRequired reports the effective required flag.
func (f IssueFormField) IsRequired() bool { return f.Required != nil && *f.Required }

// IssueFormConfig is the ordered list of create-form fields.
type IssueFormConfig struct {
	Fields []IssueFormField `json:"fields" bson:"fields"`
}

// BuiltinIssueFieldIDs lists the system field ids in TS order.
func BuiltinIssueFieldIDs() []string { return []string{"title", "body", "repo", "labels"} }

var issueFieldIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Limits shared with the TS implementation. String limits count UTF-16 code
// units, exactly like String.prototype.slice. issueTitleMax (200) and
// issueBodyMax (16 KiB) are shared with the issue store (issues.go).
const (
	issueMaxPresets = 50
	issueMaxFields  = 20
	issueMaxOptions = 30
	issueLabelMax   = 64
	issueValueMax   = 4 * 1024
)

func boolPtr(v bool) *bool { return &v }

// DefaultIssueForm returns a fresh copy of the default create form.
func DefaultIssueForm() IssueFormConfig {
	return IssueFormConfig{Fields: []IssueFormField{
		{ID: "title", Type: IssueFieldText, Label: "标题", Required: boolPtr(true), Placeholder: "一句话说明问题"},
		{ID: "body", Type: IssueFieldTextarea, Label: "问题描述", Required: boolPtr(true), Placeholder: "现象、复现步骤、期望结果…"},
		{ID: "repo", Type: IssueFieldRepo, Label: "目标仓库", Required: boolPtr(true), AllowCustom: boolPtr(true)},
		{ID: "labels", Type: IssueFieldText, Label: "标签", Required: boolPtr(false), Placeholder: "逗号分隔，如 bug, p1"},
	}}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("store: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// NewPresetID returns "repo_" + 12 random hex characters.
func NewPresetID() string { return "repo_" + randomHex(6) }

// NewFieldID returns "f_" + 8 random hex characters.
func NewFieldID() string { return "f_" + randomHex(4) }

// toGeneric converts typed Go values (e.g. []TeamRepoPreset, IssueFormConfig,
// or maps/slices containing them) into the JSON-decoded shape the normalizers
// operate on, via a JSON round trip.
func toGeneric(raw any) any {
	switch raw.(type) {
	case nil, string, float64, bool, json.Number:
		return raw
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil
	}
	return out
}

// NormalizeRepoPresets sanitizes a preset list (JSON-decoded input or
// []TeamRepoPreset): non-array input yields an empty list, invalid items are
// dropped, missing/duplicate ids are replaced with NewPresetID, and at most 50
// items are inspected.
func NormalizeRepoPresets(raw any) []TeamRepoPreset {
	items, ok := jsArray(toGeneric(raw))
	if !ok {
		return []TeamRepoPreset{}
	}
	if len(items) > issueMaxPresets {
		items = items[:issueMaxPresets]
	}
	out := []TeamRepoPreset{}
	seen := map[string]bool{}
	for _, item := range items {
		o, ok := jsObject(item)
		if !ok {
			continue
		}
		label := jsTrimStr(o["label"], issueLabelMax)
		if label == "" {
			continue
		}
		id := jsTrimStr(o["id"], 40)
		if id == "" || seen[id] {
			id = NewPresetID()
		}
		seen[id] = true
		out = append(out, TeamRepoPreset{ID: id, Label: label, Remote: jsTrimStr(o["remote"], 512)})
	}
	return out
}

func validIssueFieldType(t string) bool {
	switch t {
	case IssueFieldText, IssueFieldTextarea, IssueFieldSelect, IssueFieldMultiselect, IssueFieldRepo:
		return true
	}
	return false
}

// NormalizeIssueForm sanitizes a form configuration (JSON-decoded input,
// IssueFormConfig or *IssueFormConfig). Missing or invalid input falls back to
// DefaultIssueForm; the title field is always present and required.
func NormalizeIssueForm(raw any) IssueFormConfig {
	if config, ok := raw.(*IssueFormConfig); ok && config == nil {
		return DefaultIssueForm()
	}
	generic := toGeneric(raw)
	if !jsTruthy(generic) {
		return DefaultIssueForm()
	}
	root, ok := jsObject(generic)
	if !ok {
		return DefaultIssueForm()
	}
	fieldsIn, ok := jsArray(root["fields"])
	if !ok || len(fieldsIn) == 0 {
		return DefaultIssueForm()
	}
	if len(fieldsIn) > issueMaxFields {
		fieldsIn = fieldsIn[:issueMaxFields]
	}
	out := []IssueFormField{}
	seen := map[string]bool{}
	for _, item := range fieldsIn {
		o, ok := jsObject(item)
		if !ok {
			continue
		}
		id := jsLower(jsTrimStr(o["id"], 32))
		if !issueFieldIDPattern.MatchString(id) || seen[id] {
			continue
		}
		fieldType := ""
		if jsTruthy(o["type"]) {
			fieldType = jsString(o["type"])
		}
		if !validIssueFieldType(fieldType) {
			continue
		}
		// System field types are locked.
		switch {
		case id == "title" && fieldType != IssueFieldText,
			id == "body" && fieldType != IssueFieldTextarea && fieldType != IssueFieldText,
			id == "repo" && fieldType != IssueFieldRepo,
			id == "labels" && fieldType != IssueFieldText && fieldType != IssueFieldMultiselect:
			continue
		}
		label := jsTrimStr(o["label"], issueLabelMax)
		if label == "" {
			label = id
		}
		field := IssueFormField{ID: id, Type: fieldType, Label: label}
		if jsTruthy(o["required"]) {
			field.Required = boolPtr(true)
		}
		field.Placeholder = jsTrimStr(o["placeholder"], 120)
		if fieldType == IssueFieldSelect || fieldType == IssueFieldMultiselect {
			options := []string{}
			if values, ok := jsArray(o["options"]); ok {
				for _, value := range values {
					if option := jsTrimStr(value, issueLabelMax); option != "" {
						options = append(options, option)
					}
				}
			}
			if len(options) > issueMaxOptions {
				options = options[:issueMaxOptions]
			}
			// An empty option list would short-circuit the whitelist check and
			// accept any text, so the whole field is dropped instead.
			if len(options) == 0 {
				continue
			}
			field.Options = options
		}
		if fieldType == IssueFieldRepo {
			allowCustom, isBool := o["allowCustom"].(bool)
			field.AllowCustom = boolPtr(!(isBool && !allowCustom))
		}
		seen[id] = true
		out = append(out, field)
	}
	if !seen["title"] {
		out = append([]IssueFormField{{ID: "title", Type: IssueFieldText, Label: "标题", Required: boolPtr(true), Placeholder: "一句话说明问题"}}, out...)
	} else {
		for i := range out {
			if out[i].ID == "title" {
				out[i].Required = boolPtr(true)
				break
			}
		}
	}
	return IssueFormConfig{Fields: out}
}

// IssueFormCustomField is one validated custom field value: Value is a string
// or a []string. Custom fields are kept in form order.
type IssueFormCustomField struct {
	ID    string
	Value any
}

// IssueFormSubmission is a validated create/edit submission.
type IssueFormSubmission struct {
	Title           string
	Body            string
	Labels          []string
	TargetRepoID    string
	TargetRepoLabel string
	CustomFields    []IssueFormCustomField
}

// IssueFormError is a validation failure; Reason is one of title_required,
// body_required, labels_required, repo_required, field_required,
// invalid_option and Field names the offending field id.
type IssueFormError struct {
	Reason string
	Field  string
}

func (e *IssueFormError) Error() string { return "issue form: " + e.Reason + " (" + e.Field + ")" }

func splitLabelList(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '，' })
	out := []string{}
	for _, part := range parts {
		if trimmed := jsTrim(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseIssueLabels(raw any) []string {
	if items, ok := jsArray(raw); ok {
		labels := []string{}
		for _, item := range items {
			if label := jsTrimStr(item, issueLabelMax); label != "" {
				labels = append(labels, label)
			}
		}
		if len(labels) > 20 {
			labels = labels[:20]
		}
		if len(labels) == 0 {
			return nil
		}
		return labels
	}
	if text, ok := raw.(string); ok {
		labels := splitLabelList(text)
		if len(labels) > 20 {
			labels = labels[:20]
		}
		if len(labels) == 0 {
			return nil
		}
		return labels
	}
	return nil
}

func containsPresetID(presets []TeamRepoPreset, id string) bool {
	for _, p := range presets {
		if p.ID == id {
			return true
		}
	}
	return false
}

// ValidateIssueFormSubmission validates values (keyed by field id, as decoded
// from JSON) against the team form and presets.
func ValidateIssueFormSubmission(form IssueFormConfig, presets []TeamRepoPreset, values map[string]any) (IssueFormSubmission, *IssueFormError) {
	var result IssueFormSubmission
	fail := func(reason, field string) (IssueFormSubmission, *IssueFormError) {
		return IssueFormSubmission{}, &IssueFormError{Reason: reason, Field: field}
	}
	hasTitle := false
	for _, field := range form.Fields {
		raw := values[field.ID]
		required := field.IsRequired()
		switch {
		case field.ID == "title":
			hasTitle = true
			result.Title = jsTrimStr(raw, issueTitleMax)
			if result.Title == "" {
				return fail("title_required", "title")
			}
			continue
		case field.ID == "body":
			result.Body = jsTrimStr(raw, issueBodyMax)
			if required && result.Body == "" {
				return fail("body_required", "body")
			}
			continue
		case field.ID == "labels":
			result.Labels = parseIssueLabels(raw)
			if required && len(result.Labels) == 0 {
				return fail("labels_required", "labels")
			}
			continue
		case field.ID == "repo" || field.Type == IssueFieldRepo:
			var obj map[string]any
			if m, ok := raw.(map[string]any); ok {
				obj = m
			}
			text, isString := raw.(string)
			var idSource, labelSource any = "", ""
			if obj != nil {
				// asObj?.id ?? fallback: an explicit null/absent id falls back.
				idSource, labelSource = obj["id"], obj["label"]
			}
			if idSource == nil || obj == nil {
				idSource = ""
				if isString && containsPresetID(presets, text) {
					idSource = text
				}
			}
			if labelSource == nil || obj == nil {
				labelSource = ""
				if isString && !containsPresetID(presets, text) {
					labelSource = text
				}
			}
			id := jsTrimStr(idSource, 40)
			freeLabel := jsTrimStr(labelSource, issueLabelMax)
			var preset *TeamRepoPreset
			if id != "" {
				for i := range presets {
					if presets[i].ID == id {
						preset = &presets[i]
						break
					}
				}
			}
			allowCustom := field.AllowCustom == nil || *field.AllowCustom
			switch {
			case preset != nil:
				result.TargetRepoID = preset.ID
				result.TargetRepoLabel = preset.Label
			case freeLabel != "" && allowCustom:
				result.TargetRepoLabel = freeLabel
			case required:
				return fail("repo_required", field.ID)
			}
			if required && result.TargetRepoLabel == "" {
				return fail("repo_required", field.ID)
			}
			continue
		}

		switch field.Type {
		case IssueFieldSelect:
			v := jsTrimStr(raw, issueValueMax)
			if required && v == "" {
				return fail("field_required", field.ID)
			}
			if v != "" {
				if len(field.Options) == 0 || !contains(field.Options, v) {
					return fail("invalid_option", field.ID)
				}
				result.CustomFields = append(result.CustomFields, IssueFormCustomField{ID: field.ID, Value: v})
			}
		case IssueFieldMultiselect:
			selected := []string{}
			if items, ok := jsArray(raw); ok {
				for _, item := range items {
					if s := jsTrimStr(item, issueLabelMax); s != "" {
						selected = append(selected, s)
					}
				}
			} else if text, ok := raw.(string); ok && text != "" {
				selected = splitLabelList(text)
			}
			if required && len(selected) == 0 {
				return fail("field_required", field.ID)
			}
			if len(selected) > 0 {
				if len(field.Options) == 0 {
					return fail("invalid_option", field.ID)
				}
				for _, s := range selected {
					if !contains(field.Options, s) {
						return fail("invalid_option", field.ID)
					}
				}
				if len(selected) > issueMaxOptions {
					selected = selected[:issueMaxOptions]
				}
				result.CustomFields = append(result.CustomFields, IssueFormCustomField{ID: field.ID, Value: selected})
			}
		default: // text / textarea
			limit := issueValueMax
			if field.Type == IssueFieldTextarea {
				limit = issueBodyMax
			}
			v := jsTrimStr(raw, limit)
			if required && v == "" {
				return fail("field_required", field.ID)
			}
			if v != "" {
				result.CustomFields = append(result.CustomFields, IssueFormCustomField{ID: field.ID, Value: v})
			}
		}
	}
	// A form without a title field can never produce a valid issue.
	if !hasTitle {
		return fail("title_required", "title")
	}
	return result, nil
}

// ResolveTeamIssueSettings returns the team's normalized presets and form,
// defaulting to an empty preset list and DefaultIssueForm.
func ResolveTeamIssueSettings(team TeamDoc) ([]TeamRepoPreset, IssueFormConfig) {
	var form any
	if team.IssueForm != nil {
		form = *team.IssueForm
	}
	return NormalizeRepoPresets(team.RepoPresets), NormalizeIssueForm(form)
}
