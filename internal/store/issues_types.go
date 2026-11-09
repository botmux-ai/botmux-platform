package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

// Issue Board persistence types (src/store/issues.ts, DESIGN-issue-board.md
// v13). The read structs double as the API JSON: TS returns IssueDoc /
// IssueEventDoc verbatim. A struct decoded from BSON renders JSON from the
// stored bytes in physical field order (issues_json.go); one built in memory
// uses the json tags, which follow the TS insert literals. Writes never
// marshal these structs directly; see issueRecord and friends, which carry the
// BSON numeric types the Node driver produces.

type IssueStatus string

const (
	IssueOpen           IssueStatus = "open"
	IssueClaimed        IssueStatus = "claimed"
	IssueInProgress     IssueStatus = "in_progress"
	IssueInReview       IssueStatus = "in_review"
	IssueDone           IssueStatus = "done"
	IssueCancelling     IssueStatus = "cancelling"
	IssueNeedsAttention IssueStatus = "needs_attention"
	IssueReopened       IssueStatus = "reopened"
)

type AttentionReason string

const (
	AttentionCancelDeliveryTimeout AttentionReason = "cancel_delivery_timeout"
	AttentionClaimActivateTimeout  AttentionReason = "claim_activate_timeout"
	AttentionTaskBlocked           AttentionReason = "task_blocked"
	AttentionRunTimeout            AttentionReason = "run_timeout"
)

type IssueEventKind string

const (
	IssueEventCreated       IssueEventKind = "created"
	IssueEventClaimed       IssueEventKind = "claimed"
	IssueEventBound         IssueEventKind = "bound"
	IssueEventStatus        IssueEventKind = "status"
	IssueEventReopened      IssueEventKind = "reopened"
	IssueEventReleased      IssueEventKind = "released"
	IssueEventArchived      IssueEventKind = "archived"
	IssueEventLeaseExpired  IssueEventKind = "lease_expired"
	IssueEventForceDetached IssueEventKind = "force_detached"
)

const (
	// ClaimLeaseMS is the unbound reservation lease; bind resets the lease to
	// ActivationLeaseMS (§六).
	ClaimLeaseMS      int64 = 15 * 60 * 1000
	ActivationLeaseMS int64 = 5 * 60 * 1000

	// ClaimLease and ActivationLease are the same windows as durations.
	ClaimLease      = time.Duration(ClaimLeaseMS) * time.Millisecond
	ActivationLease = time.Duration(ActivationLeaseMS) * time.Millisecond
)

// IssueClaim is the embedded claim. LocalTaskRef/Label/URL come last because
// bind appends them to an existing claim subdocument.
type IssueClaim struct {
	ClaimID string `json:"claimId" bson:"claimId"`
	// ClaimEpoch snapshots issue.claimEpochCounter at claim time (the fence).
	ClaimEpoch int64  `json:"claimEpoch" bson:"claimEpoch,truncate"`
	UnionID    string `json:"unionId" bson:"unionId"`
	Name       string `json:"name" bson:"name"`
	MachineID  string `json:"machineId" bson:"machineId"`
	// Agent and RepoLabel are whatever JSON value the claiming client sent
	// (TS persists any truthy value verbatim; the daemon sends a string, other
	// clients an object): string, bson.D, bson.A, bool or a number.
	Agent          any   `json:"agent,omitempty" bson:"agent,omitempty"`
	RepoLabel      any   `json:"repoLabel,omitempty" bson:"repoLabel,omitempty"`
	ClaimedAt      int64 `json:"claimedAt" bson:"claimedAt,truncate"`
	LeaseExpiresAt int64 `json:"leaseExpiresAt" bson:"leaseExpiresAt,truncate"`
	Bound          bool  `json:"bound" bson:"bound"`
	// LastSourceSeq is client-supplied (any JS number), so it keeps float64
	// rather than truncating a value TS would compare exactly.
	LastSourceSeq float64 `json:"lastSourceSeq" bson:"lastSourceSeq"`
	// LocalTaskRef is <runtimeTargetId>::<localTaskId>.
	LocalTaskRef string `json:"localTaskRef,omitempty" bson:"localTaskRef,omitempty"`
	// LocalTaskLabel is display-only (the issue chat name); never used for
	// matching.
	LocalTaskLabel string `json:"localTaskLabel,omitempty" bson:"localTaskLabel,omitempty"`
	// LocalTaskURL is rendered as a link; the bind caller must only pass https.
	LocalTaskURL string `json:"localTaskUrl,omitempty" bson:"localTaskUrl,omitempty"`

	raw bson.Raw
}

func (c *IssueClaim) UnmarshalBSON(data []byte) error {
	type plain IssueClaim
	var decoded plain
	if err := unmarshalLenient(data, &decoded); err != nil {
		return err
	}
	*c = IssueClaim(decoded)
	c.raw = append(bson.Raw(nil), data...)
	return nil
}

func (c IssueClaim) MarshalJSON() ([]byte, error) {
	if c.raw != nil {
		return jsJSONFromBSON(c.raw)
	}
	type plain IssueClaim
	return marshalJSONNoEscape(plain(c))
}

// IssueDoc mirrors the issues collection. Labels and SuggestedAssigneeUnionID
// are pointers because TS persists (and returns) an explicitly empty value
// distinctly from an absent one.
type IssueDoc struct {
	ID              string            `json:"_id" bson:"_id"`
	TeamID          string            `json:"teamId" bson:"teamId"`
	Title           string            `json:"title" bson:"title"`
	Body            string            `json:"body" bson:"body"`
	Status          IssueStatus       `json:"status" bson:"status"`
	Labels          *[]string         `json:"labels,omitempty" bson:"labels,omitempty"`
	TargetRepoID    string            `json:"targetRepoId,omitempty" bson:"targetRepoId,omitempty"`
	TargetRepoLabel string            `json:"targetRepoLabel,omitempty" bson:"targetRepoLabel,omitempty"`
	CustomFields    IssueCustomFields `json:"customFields,omitempty" bson:"customFields,omitempty"`
	// SuggestedAssigneeUnionID is advisory and never gates claiming.
	SuggestedAssigneeUnionID *string `json:"suggestedAssigneeUnionId,omitempty" bson:"suggestedAssigneeUnionId,omitempty"`
	CreatedBy                string  `json:"createdBy" bson:"createdBy"`
	CreatedByName            string  `json:"createdByName" bson:"createdByName"`
	CreatedAt                int64   `json:"createdAt" bson:"createdAt,truncate"`
	UpdatedAt                int64   `json:"updatedAt" bson:"updatedAt,truncate"`
	// Rev guards body/label edits; StateRev guards state transitions so status
	// write-back does not conflict with edits.
	Rev               int64       `json:"rev" bson:"rev,truncate"`
	StateRev          int64       `json:"stateRev" bson:"stateRev,truncate"`
	ClaimEpochCounter int64       `json:"claimEpochCounter" bson:"claimEpochCounter,truncate"`
	EventSeq          int64       `json:"eventSeq" bson:"eventSeq,truncate"`
	Claim             *IssueClaim `json:"claim,omitempty" bson:"claim,omitempty"`
	// CancelCommandID is reserved for the P2 command channel.
	CancelCommandID string          `json:"cancelCommandId,omitempty" bson:"cancelCommandId,omitempty"`
	AttentionSince  int64           `json:"attentionSince,omitempty" bson:"attentionSince,omitempty,truncate"`
	AttentionReason AttentionReason `json:"attentionReason,omitempty" bson:"attentionReason,omitempty"`
	ArchivedAt      int64           `json:"archivedAt,omitempty" bson:"archivedAt,omitempty,truncate"`

	raw bson.Raw
}

func (d *IssueDoc) UnmarshalBSON(data []byte) error {
	type plain IssueDoc
	var decoded plain
	if err := unmarshalLenient(data, &decoded); err != nil {
		return err
	}
	*d = IssueDoc(decoded)
	d.raw = append(bson.Raw(nil), data...)
	return nil
}

func (d IssueDoc) MarshalJSON() ([]byte, error) {
	if d.raw != nil {
		return jsJSONFromBSON(d.raw)
	}
	type plain IssueDoc
	return marshalJSONNoEscape(plain(d))
}

// IssueEventDoc mirrors issue_events in the TS insert literal's order.
type IssueEventDoc struct {
	ID           string         `json:"_id" bson:"_id"`
	IssueID      string         `json:"issueId" bson:"issueId"`
	TeamID       string         `json:"teamId" bson:"teamId"`
	Seq          int64          `json:"seq" bson:"seq,truncate"`
	At           int64          `json:"at" bson:"at,truncate"`
	Kind         IssueEventKind `json:"kind" bson:"kind"`
	FromStatus   IssueStatus    `json:"fromStatus,omitempty" bson:"fromStatus,omitempty"`
	ToStatus     IssueStatus    `json:"toStatus,omitempty" bson:"toStatus,omitempty"`
	ActorUnionID string         `json:"actorUnionId" bson:"actorUnionId"`
	Detail       string         `json:"detail,omitempty" bson:"detail,omitempty"`

	raw bson.Raw
}

func (e *IssueEventDoc) UnmarshalBSON(data []byte) error {
	type plain IssueEventDoc
	var decoded plain
	if err := unmarshalLenient(data, &decoded); err != nil {
		return err
	}
	*e = IssueEventDoc(decoded)
	e.raw = append(bson.Raw(nil), data...)
	return nil
}

func (e IssueEventDoc) MarshalJSON() ([]byte, error) {
	if e.raw != nil {
		return jsJSONFromBSON(e.raw)
	}
	type plain IssueEventDoc
	return marshalJSONNoEscape(plain(e))
}

// IssueCustomField is one team-defined form value: Value is a string or a
// []string (TS Record<string, string | string[]>).
type IssueCustomField struct {
	ID    string
	Value any
}

// IssueCustomFields keeps insertion order. The board renders
// Object.entries(customFields), so a Go map (random BSON order, sorted JSON
// keys) would visibly reorder fields.
type IssueCustomFields []IssueCustomField

// Get returns the value for id.
func (f IssueCustomFields) Get(id string) (any, bool) {
	for _, field := range f {
		if field.ID == id {
			return field.Value, true
		}
	}
	return nil, false
}

func (f IssueCustomFields) MarshalBSONValue() (bsontype.Type, []byte, error) {
	doc := make(bson.D, 0, len(f))
	for _, field := range f {
		doc = append(doc, bson.E{Key: field.ID, Value: field.Value})
	}
	raw, err := bson.Marshal(doc)
	if err != nil {
		return 0, nil, err
	}
	return bsontype.EmbeddedDocument, raw, nil
}

func (f *IssueCustomFields) UnmarshalBSONValue(t bsontype.Type, data []byte) error {
	switch t {
	case bsontype.Null, bsontype.Undefined:
		*f = nil
		return nil
	case bsontype.EmbeddedDocument:
	default:
		return fmt.Errorf("store: customFields must be a document, got %s", t)
	}
	elements, err := bson.Raw(data).Elements()
	if err != nil {
		return err
	}
	out := make(IssueCustomFields, 0, len(elements))
	for _, element := range elements {
		value, err := customFieldValue(element.Value())
		if err != nil {
			return err
		}
		out = append(out, IssueCustomField{ID: element.Key(), Value: value})
	}
	*f = out
	return nil
}

func customFieldValue(raw bson.RawValue) (any, error) {
	if text, ok := raw.StringValueOK(); ok {
		return text, nil
	}
	if raw.Type == bsontype.Array {
		var list []string
		if err := raw.Unmarshal(&list); err == nil {
			if list == nil {
				list = []string{}
			}
			return list, nil
		}
	}
	// Not produced by the form validator; keep whatever is stored so a read
	// never fails on legacy data.
	var value any
	if err := raw.Unmarshal(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func (f IssueCustomFields) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	// encoding/json re-applies HTML escaping to Marshaler output only when the
	// outer encoder asks for it, so writeJSON keeps JSON.stringify bytes.
	encoder.SetEscapeHTML(false)
	out.WriteByte('{')
	for i, field := range f {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := encoder.Encode(field.ID); err != nil {
			return nil, err
		}
		trimNewline(&out)
		out.WriteByte(':')
		if err := encoder.Encode(field.Value); err != nil {
			return nil, err
		}
		trimNewline(&out)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func (f *IssueCustomFields) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		*f = nil
		return nil
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("store: customFields must be an object")
	}
	out := IssueCustomFields{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		if list, ok := value.([]any); ok {
			strs := make([]string, 0, len(list))
			for _, item := range list {
				text, ok := item.(string)
				if !ok {
					strs = nil
					break
				}
				strs = append(strs, text)
			}
			if strs != nil {
				value = strs
			}
		}
		out = append(out, IssueCustomField{ID: key.(string), Value: value})
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	*f = out
	return nil
}

func trimNewline(buf *bytes.Buffer) {
	if n := buf.Len(); n > 0 && buf.Bytes()[n-1] == '\n' {
		buf.Truncate(n - 1)
	}
}

// ---- write shapes ----

// issueRecord is the createIssue insert literal: same key order, ms
// timestamps as double and counters as int32 like the Node driver writes.
type issueRecord struct {
	ID                       string            `bson:"_id"`
	TeamID                   string            `bson:"teamId"`
	Title                    string            `bson:"title"`
	Body                     string            `bson:"body"`
	Status                   IssueStatus       `bson:"status"`
	Labels                   *[]string         `bson:"labels,omitempty"`
	TargetRepoID             string            `bson:"targetRepoId,omitempty"`
	TargetRepoLabel          string            `bson:"targetRepoLabel,omitempty"`
	CustomFields             IssueCustomFields `bson:"customFields,omitempty"`
	SuggestedAssigneeUnionID string            `bson:"suggestedAssigneeUnionId,omitempty"`
	CreatedBy                string            `bson:"createdBy"`
	CreatedByName            string            `bson:"createdByName"`
	CreatedAt                float64           `bson:"createdAt"`
	UpdatedAt                float64           `bson:"updatedAt"`
	Rev                      int32             `bson:"rev"`
	StateRev                 int32             `bson:"stateRev"`
	ClaimEpochCounter        int32             `bson:"claimEpochCounter"`
	EventSeq                 int32             `bson:"eventSeq"`
}

// issueClaimRecord is the claimIssue claim literal.
type issueClaimRecord struct {
	ClaimID        string  `bson:"claimId"`
	ClaimEpoch     any     `bson:"claimEpoch"`
	UnionID        string  `bson:"unionId"`
	Name           string  `bson:"name"`
	MachineID      string  `bson:"machineId"`
	Agent          any     `bson:"agent,omitempty"`
	RepoLabel      any     `bson:"repoLabel,omitempty"`
	ClaimedAt      float64 `bson:"claimedAt"`
	LeaseExpiresAt float64 `bson:"leaseExpiresAt"`
	Bound          bool    `bson:"bound"`
	LastSourceSeq  int32   `bson:"lastSourceSeq"`
}

// issueEventRecord is the appendEvent insert literal.
type issueEventRecord struct {
	ID           string         `bson:"_id"`
	IssueID      string         `bson:"issueId"`
	TeamID       string         `bson:"teamId"`
	Seq          any            `bson:"seq"`
	At           float64        `bson:"at"`
	Kind         IssueEventKind `bson:"kind"`
	FromStatus   IssueStatus    `bson:"fromStatus,omitempty"`
	ToStatus     IssueStatus    `bson:"toStatus,omitempty"`
	ActorUnionID string         `bson:"actorUnionId"`
	Detail       string         `bson:"detail,omitempty"`
}
