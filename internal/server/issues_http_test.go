package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"go.mongodb.org/mongo-driver/bson"
)

// Handler-level ports of test/server-machine-issues.test.ts and
// test/issues-core-claim-machine.test.ts, plus the web, desktop and team
// issue-settings entries of src/server/issues-http.ts. The issue store runs on
// the in-memory Mongo-semantics database (key order there is not stable, so
// assertions decode the JSON).

const (
	issuesTestTeam     = "a1b2c3d4e5f60718"
	issuesTestMachine  = "a1a1a1a1a1a1a1a1"
	issuesTestMachine2 = "a2a2a2a2a2a2a2a2"
	issuesTestCarolBox = "c3c3c3c3c3c3c3c3"
)

type issuesHarness struct {
	t      *testing.T
	a      *Apex
	repo   *store.DocumentRepository
	issues *store.IssueStore
}

func newIssuesHarness(t *testing.T) *issuesHarness {
	t.Helper()
	cfg := machineRouteTestConfig()
	cfg.MachineTokenTTL = time.Hour
	repo := newMemoryRepository()
	issues := store.NewIssueStore(store.StaticDatabaseProvider{DB: store.NewMemoryDatabase()})
	h := &issuesHarness{
		t:      t,
		a:      &Apex{Config: cfg, Repository: repo, DesktopSessions: repo, IssueStore: issues},
		repo:   repo,
		issues: issues,
	}
	err := repo.CreateTeam(context.Background(), store.TeamDoc{
		ID: issuesTestTeam, Name: "Team", Members: []string{"u-alice"}, CreatedBy: "u-alice", CreatedAt: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *issuesHarness) seedMachine(machineID, unionID string) {
	h.t.Helper()
	if err := seedMachine(h.repo, store.RegisterMachine{
		MachineID: machineID, UnionID: unionID, OwnerName: unionID, Name: "box", BotmuxVersion: "1.0.0",
		DashboardPort: 8800, LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *issuesHarness) addMember(unionID string) {
	h.t.Helper()
	if err := h.repo.AddTeamMember(context.Background(), issuesTestTeam, unionID); err != nil {
		h.t.Fatal(err)
	}
}

func (h *issuesHarness) machineToken(machineID, unionID string) string {
	return auth.MintMachineToken(h.a.Config, auth.MachineIdentity{UnionID: unionID, OwnerName: unionID, MachineID: machineID})
}

func (h *issuesHarness) sessionCookie(unionID string) string {
	return auth.SessionCookieName + "=" + auth.MintSession(h.a.Config, auth.SessionUser{UnionID: unionID, Name: unionID})
}

func (h *issuesHarness) desktopToken(unionID string) string {
	return auth.MintDesktopSession(h.a.Config, auth.DesktopSessionInput{UnionID: unionID, Name: unionID, LocalProfileID: "profile-1"}).AccessToken
}

type issuesCall struct {
	method string
	path   string
	body   any // string = raw bytes; anything else is JSON-encoded
	bearer string
	cookie string
	origin bool
}

func (h *issuesHarness) do(c issuesCall) *httptest.ResponseRecorder {
	h.t.Helper()
	if c.method == "" {
		c.method = http.MethodGet
	}
	var reader *bytes.Reader
	switch body := c.body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case string:
		reader = bytes.NewReader([]byte(body))
	default:
		data, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	request := httptest.NewRequest(c.method, "http://localhost"+c.path, reader)
	if c.body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.bearer != "" {
		request.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.cookie != "" {
		request.Header.Set("Cookie", c.cookie)
	}
	if c.origin {
		request.Header.Set("Origin", "https://botmux.example")
	}
	recorder := httptest.NewRecorder()
	h.a.ServeHTTP(recorder, request)
	return recorder
}

func issuesDecode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %d %q: %v", rec.Code, rec.Body.String(), err)
	}
	return out
}

func issuesExpect(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) map[string]any {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body.String(), status)
	}
	body := issuesDecode(t, rec)
	if code != "" && body["error"] != code {
		t.Fatalf("error = %v (%s), want %q", body["error"], rec.Body.String(), code)
	}
	return body
}

func issuesPath(body map[string]any, keys ...string) any {
	var cur any = body
	for _, key := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[key]
	}
	return cur
}

func (h *issuesHarness) seedOpenIssue() store.IssueDoc {
	h.t.Helper()
	doc, err := h.issues.Create(context.Background(), store.CreateIssueInput{
		TeamID: issuesTestTeam, Title: "fix the thing", Body: "b", CreatedBy: "u-alice", CreatedByName: "Alice",
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return doc
}

type issuesClaimed struct {
	issueID    string
	claimID    string
	claimEpoch float64
	stateRev   float64
}

// seedClaimed claims a fresh issue from issuesTestMachine via the machine
// entry (the TS seedClaimed helper).
func (h *issuesHarness) seedClaimed() issuesClaimed {
	h.t.Helper()
	h.seedMachine(issuesTestMachine, "u-alice")
	issue := h.seedOpenIssue()
	rec := h.do(issuesCall{
		method: http.MethodPost, path: "/v1/machine/issues/" + issue.ID + "/claim",
		bearer: h.machineToken(issuesTestMachine, "u-alice"),
		body:   map[string]any{"claimId": "c1", "expectedStateRev": issue.StateRev},
	})
	body := issuesExpect(h.t, rec, http.StatusOK, "")
	return issuesClaimed{
		issueID:    issue.ID,
		claimID:    issuesPath(body, "claim", "claimId").(string),
		claimEpoch: issuesPath(body, "claim", "claimEpoch").(float64),
		stateRev:   issuesPath(body, "issue", "stateRev").(float64),
	}
}

// ---- machine entry: auth gates ----

func TestMachineIssuesAuthGates(t *testing.T) {
	h := newIssuesHarness(t)
	h.seedMachine(issuesTestMachine, "u-alice")
	h.seedMachine(issuesTestMachine2, "u-bob")

	assertJSONError(t, h.do(issuesCall{path: "/v1/machine/teams"}), http.StatusUnauthorized, "invalid_machine_token")
	assertJSONError(t, h.do(issuesCall{path: "/v1/machine/teams", bearer: "garbage.token.here"}), http.StatusUnauthorized, "invalid_machine_token")
	// Valid signature, but the machine does not exist.
	assertJSONError(t, h.do(issuesCall{path: "/v1/machine/teams", bearer: h.machineToken("deadbeefdeadbeef", "u-alice")}), http.StatusForbidden, "machine_ownership_mismatch")
	// The machine now belongs to someone else than the token says.
	assertJSONError(t, h.do(issuesCall{path: "/v1/machine/teams", bearer: h.machineToken(issuesTestMachine2, "u-alice")}), http.StatusForbidden, "machine_ownership_mismatch")

	// Unbind cutoff later than the token's iat → revoked; a token minted after
	// the cutoff (rebind) passes.
	ctx := context.Background()
	h.a.KV = store.NewKVStore(store.NewMemoryKV(), "t", time.Minute, time.Minute)
	old := auth.MintMachineTokenAt(h.a.Config, auth.MachineIdentity{UnionID: "u-alice", OwnerName: "Alice", MachineID: issuesTestMachine}, time.Now().Add(-2*time.Minute))
	if err := h.a.KV.RevokeMachineToken(ctx, issuesTestMachine, time.Now().Add(-time.Minute).UnixMilli(), time.Hour); err != nil {
		t.Fatal(err)
	}
	assertJSONError(t, h.do(issuesCall{path: "/v1/machine/teams", bearer: old}), http.StatusUnauthorized, "machine_revoked")
	if rec := h.do(issuesCall{path: "/v1/machine/teams", bearer: h.machineToken(issuesTestMachine, "u-alice")}); rec.Code != http.StatusOK {
		t.Fatalf("token after cutoff = %d %s", rec.Code, rec.Body.String())
	}
	h.a.KV = nil

	if err := h.repo.RetireMachine(ctx, issuesTestMachine); err != nil {
		t.Fatal(err)
	}
	assertJSONError(t, h.do(issuesCall{path: "/v1/machine/teams", bearer: h.machineToken(issuesTestMachine, "u-alice")}), http.StatusForbidden, "machine_ownership_mismatch")
}

// ---- machine entry: reads ----

func TestMachineIssuesReads(t *testing.T) {
	h := newIssuesHarness(t)
	h.seedMachine(issuesTestMachine, "u-alice")
	token := h.machineToken(issuesTestMachine, "u-alice")

	rec := h.do(issuesCall{path: "/v1/machine/teams", bearer: token})
	if rec.Code != http.StatusOK || rec.Body.String() != `{"teams":[{"teamId":"`+issuesTestTeam+`","teamName":"Team"}]}` || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("teams = %d %q %q", rec.Code, rec.Body.String(), rec.Header().Get("Cache-Control"))
	}

	h.seedOpenIssue()
	rec = h.do(issuesCall{path: "/v1/machine/issues?teamId=" + issuesTestTeam, bearer: token})
	body := issuesExpect(t, rec, http.StatusOK, "")
	todo, _ := issuesPath(body, "sections", "todo").([]any)
	if len(todo) != 1 || todo[0].(map[string]any)["title"] != "fix the thing" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("list = %s", rec.Body.String())
	}
	for _, section := range []string{"needsAttention", "inProgress", "inReview", "done"} {
		if list, ok := issuesPath(body, "sections", section).([]any); !ok || len(list) != 0 {
			t.Fatalf("section %s = %v", section, issuesPath(body, "sections", section))
		}
	}

	assertJSONError(t, h.do(issuesCall{path: "/v1/machine/issues", bearer: token}), http.StatusBadRequest, "missing_teamId")

	// Not the owner's team → 404 (does not reveal that the team exists).
	h.seedMachine(issuesTestCarolBox, "u-carol")
	assertJSONError(t, h.do(issuesCall{path: "/v1/machine/issues?teamId=" + issuesTestTeam, bearer: h.machineToken(issuesTestCarolBox, "u-carol")}), http.StatusNotFound, "not_found")
}

// ---- machine entry: claim (the token decides the machine) ----

func TestMachineIssuesClaim(t *testing.T) {
	h := newIssuesHarness(t)
	h.seedMachine(issuesTestMachine, "u-alice")
	h.seedMachine(issuesTestMachine2, "u-alice")
	token := h.machineToken(issuesTestMachine, "u-alice")
	claimPath := func(id string) string { return "/v1/machine/issues/" + id + "/claim" }

	t.Run("without machineId uses the token's machine", func(t *testing.T) {
		issue := h.seedOpenIssue()
		rec := h.do(issuesCall{method: http.MethodPost, path: claimPath(issue.ID), bearer: token, body: map[string]any{"claimId": "c1", "expectedStateRev": issue.StateRev}})
		body := issuesExpect(t, rec, http.StatusOK, "")
		if issuesPath(body, "claim", "machineId") != issuesTestMachine || issuesPath(body, "claim", "unionId") != "u-alice" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("claim = %s", rec.Body.String())
		}
	})

	t.Run("machineId other than the token's is machine_mismatch", func(t *testing.T) {
		issue := h.seedOpenIssue()
		rec := h.do(issuesCall{method: http.MethodPost, path: claimPath(issue.ID), bearer: token, body: map[string]any{"claimId": "c1", "machineId": "m-other", "expectedStateRev": issue.StateRev}})
		assertJSONError(t, rec, http.StatusForbidden, "machine_mismatch")
	})

	t.Run("same claimId from another machine is already_claimed", func(t *testing.T) {
		issue := h.seedOpenIssue()
		first := issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: claimPath(issue.ID), bearer: token, body: map[string]any{"claimId": "shared-key", "expectedStateRev": issue.StateRev}}), http.StatusOK, "")
		second := h.do(issuesCall{
			method: http.MethodPost, path: claimPath(issue.ID), bearer: h.machineToken(issuesTestMachine2, "u-alice"),
			body: map[string]any{"claimId": "shared-key", "expectedStateRev": issuesPath(first, "issue", "stateRev")},
		})
		assertJSONError(t, second, http.StatusConflict, "already_claimed")
	})

	t.Run("same claimId retried from the same machine is idempotent", func(t *testing.T) {
		issue := h.seedOpenIssue()
		first := issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: claimPath(issue.ID), bearer: token, body: map[string]any{"claimId": "c-retry", "expectedStateRev": issue.StateRev}}), http.StatusOK, "")
		retry := issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: claimPath(issue.ID), bearer: token, body: map[string]any{"claimId": "c-retry", "expectedStateRev": issuesPath(first, "issue", "stateRev")}}), http.StatusOK, "")
		if issuesPath(retry, "claim", "claimId") != "c-retry" || issuesPath(retry, "claim", "claimEpoch") != issuesPath(first, "claim", "claimEpoch") {
			t.Fatalf("retry = %v first = %v", retry, first)
		}
	})

	t.Run("missing expectedStateRev is invalid", func(t *testing.T) {
		issue := h.seedOpenIssue()
		assertJSONError(t, h.do(issuesCall{method: http.MethodPost, path: claimPath(issue.ID), bearer: token, body: map[string]any{"claimId": "c1"}}), http.StatusBadRequest, "invalid")
		assertJSONError(t, h.do(issuesCall{method: http.MethodPost, path: claimPath(issue.ID), bearer: token, body: map[string]any{"claimId": "c1", "expectedStateRev": "1"}}), http.StatusBadRequest, "invalid")
		assertJSONError(t, h.do(issuesCall{method: http.MethodPost, path: claimPath(issue.ID), bearer: token, body: "not json"}), http.StatusBadRequest, "invalid")
	})

	t.Run("agent and repoLabel are persisted verbatim", func(t *testing.T) {
		issue := h.seedOpenIssue()
		rec := h.do(issuesCall{method: http.MethodPost, path: claimPath(issue.ID), bearer: token, body: `{"claimId":"c-agent","agent":{"appId":"cli_x","name":"Bot","n":3},"repoLabel":"platform","expectedStateRev":` + issueJSONNumber(float64(issue.StateRev)) + `}`})
		body := issuesExpect(t, rec, http.StatusOK, "")
		agent, _ := issuesPath(body, "claim", "agent").(map[string]any)
		if agent["appId"] != "cli_x" || agent["n"] != float64(3) || issuesPath(body, "claim", "repoLabel") != "platform" {
			t.Fatalf("claim = %s", rec.Body.String())
		}
		stored, err := h.issues.Get(context.Background(), issue.ID)
		if err != nil {
			t.Fatal(err)
		}
		// The in-memory database does not keep key order; compare the value.
		data, _ := json.Marshal(stored.Claim)
		var claim map[string]any
		if err := json.Unmarshal(data, &claim); err != nil {
			t.Fatal(err)
		}
		if agent, _ := claim["agent"].(map[string]any); len(agent) != 3 || agent["appId"] != "cli_x" || agent["name"] != "Bot" || agent["n"] != float64(3) {
			t.Fatalf("stored claim = %s", data)
		}
	})
}

func issueJSONNumber(v float64) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// ---- machine entry: bind (fenced to the claiming machine) ----

func TestMachineIssuesBind(t *testing.T) {
	bind := func(h *issuesHarness, c issuesClaimed, extra map[string]any, machineID string) *httptest.ResponseRecorder {
		body := map[string]any{"claimId": c.claimID, "localTaskRef": "oc_g1::cli_x", "expectedStateRev": c.stateRev}
		for k, v := range extra {
			body[k] = v
		}
		return h.do(issuesCall{method: http.MethodPost, path: "/v1/machine/issues/" + c.issueID + "/bind", bearer: h.machineToken(machineID, "u-alice"), body: body})
	}

	t.Run("own machine binds", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		rec := bind(h, c, map[string]any{"localTaskRef": "cli_x::s-1"}, issuesTestMachine)
		body := issuesExpect(t, rec, http.StatusOK, "")
		if issuesPath(body, "issue", "claim", "localTaskRef") != "cli_x::s-1" || issuesPath(body, "issue", "claim", "bound") != true || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("bind = %s", rec.Body.String())
		}
	})

	t.Run("label and https applink are stored", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		body := issuesExpect(t, bind(h, c, map[string]any{
			"localTaskLabel": "修一个 bug #a1b2c3d4",
			"localTaskUrl":   "https://applink.feishu.cn/client/chat/open?openChatId=oc_g1",
		}, issuesTestMachine), http.StatusOK, "")
		if issuesPath(body, "issue", "claim", "localTaskLabel") != "修一个 bug #a1b2c3d4" ||
			issuesPath(body, "issue", "claim", "localTaskUrl") != "https://applink.feishu.cn/client/chat/open?openChatId=oc_g1" {
			t.Fatalf("bind = %v", body)
		}
	})

	t.Run("display fields are optional and never stored empty", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		body := issuesExpect(t, bind(h, c, map[string]any{"localTaskLabel": "  \n ", "localTaskUrl": 42}, issuesTestMachine), http.StatusOK, "")
		claim := issuesPath(body, "issue", "claim").(map[string]any)
		if _, ok := claim["localTaskLabel"]; ok {
			t.Fatalf("label stored: %v", claim)
		}
		if _, ok := claim["localTaskUrl"]; ok {
			t.Fatalf("url stored: %v", claim)
		}
	})

	for _, bad := range []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"http://applink.feishu.cn/x",
		"file:///etc/passwd",
		"不是一个 URL",
	} {
		t.Run("drops non-https deep link "+bad, func(t *testing.T) {
			h := newIssuesHarness(t)
			c := h.seedClaimed()
			body := issuesExpect(t, bind(h, c, map[string]any{"localTaskUrl": bad}, issuesTestMachine), http.StatusOK, "")
			if _, ok := issuesPath(body, "issue", "claim").(map[string]any)["localTaskUrl"]; ok {
				t.Fatalf("url stored: %v", body)
			}
		})
	}

	t.Run("label control characters are flattened and the label truncated", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		body := issuesExpect(t, bind(h, c, map[string]any{"localTaskLabel": "a\nb\tc" + strings.Repeat("x", 300)}, issuesTestMachine), http.StatusOK, "")
		label := issuesPath(body, "issue", "claim", "localTaskLabel").(string)
		if strings.ContainsAny(label, "\r\n\t") || len(label) != 120 || !strings.HasPrefix(label, "a b c") {
			t.Fatalf("label = %q", label)
		}
	})

	t.Run("another machine of the same owner is machine_mismatch", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		h.seedMachine(issuesTestMachine2, "u-alice")
		assertJSONError(t, bind(h, c, nil, issuesTestMachine2), http.StatusForbidden, "machine_mismatch")
	})

	t.Run("missing localTaskRef is invalid", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		assertJSONError(t, bind(h, c, map[string]any{"localTaskRef": ""}, issuesTestMachine), http.StatusBadRequest, "invalid")
	})
}

// ---- machine entry: status write-back ----

func TestMachineIssuesStatus(t *testing.T) {
	status := func(h *issuesHarness, c issuesClaimed, target string, stateRev float64, machineID string) *httptest.ResponseRecorder {
		return h.do(issuesCall{
			method: http.MethodPost, path: "/v1/machine/issues/" + c.issueID + "/status", bearer: h.machineToken(machineID, "u-alice"),
			body: map[string]any{"claimId": c.claimID, "claimEpoch": c.claimEpoch, "sourceSeq": 1, "status": target, "expectedStateRev": stateRev},
		})
	}

	t.Run("own machine moves claimed to in_progress", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		body := issuesExpect(t, status(h, c, "in_progress", c.stateRev, issuesTestMachine), http.StatusOK, "")
		if issuesPath(body, "issue", "status") != "in_progress" {
			t.Fatalf("status = %v", body)
		}
	})

	t.Run("another machine of the same owner is machine_mismatch", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		h.seedMachine(issuesTestMachine2, "u-alice")
		assertJSONError(t, status(h, c, "in_progress", c.stateRev, issuesTestMachine2), http.StatusForbidden, "machine_mismatch")
	})

	t.Run("terminal retry after the claim is cleared still answers 200", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		first := issuesExpect(t, status(h, c, "open", c.stateRev, issuesTestMachine), http.StatusOK, "")
		if issuesPath(first, "issue", "status") != "open" || issuesPath(first, "issue", "claim") != nil {
			t.Fatalf("first = %v", first)
		}
		retry := status(h, c, "open", issuesPath(first, "issue", "stateRev").(float64), issuesTestMachine)
		if retry.Code != http.StatusOK {
			t.Fatalf("retry = %d %s", retry.Code, retry.Body.String())
		}
	})

	for _, target := range []string{"done", "open", "reopened"} {
		t.Run(target+" clears the claim", func(t *testing.T) {
			h := newIssuesHarness(t)
			c := h.seedClaimed()
			body := issuesExpect(t, status(h, c, target, c.stateRev, issuesTestMachine), http.StatusOK, "")
			if issuesPath(body, "issue", "status") != target {
				t.Fatalf("status = %v", body)
			}
			if _, ok := body["issue"].(map[string]any)["claim"]; ok {
				t.Fatalf("claim kept: %v", body)
			}
		})
	}

	t.Run("invalid bodies", func(t *testing.T) {
		h := newIssuesHarness(t)
		c := h.seedClaimed()
		path := "/v1/machine/issues/" + c.issueID + "/status"
		token := h.machineToken(issuesTestMachine, "u-alice")
		for _, body := range []any{
			map[string]any{"claimId": c.claimID, "status": "in_review"},
			map[string]any{"claimId": c.claimID, "claimEpoch": c.claimEpoch, "sourceSeq": 1, "status": "", "expectedStateRev": c.stateRev},
			map[string]any{"claimId": c.claimID, "claimEpoch": c.claimEpoch, "sourceSeq": 1, "status": 7, "expectedStateRev": c.stateRev},
			map[string]any{"claimId": c.claimID, "claimEpoch": c.claimEpoch, "sourceSeq": 1, "status": "in_progress", "attentionReason": 1, "expectedStateRev": c.stateRev},
		} {
			assertJSONError(t, h.do(issuesCall{method: http.MethodPost, path: path, bearer: token, body: body}), http.StatusBadRequest, "invalid")
		}
	})
}

// ---- machine entry: only the daemon's endpoints ----

func TestMachineIssuesRouteSurface(t *testing.T) {
	h := newIssuesHarness(t)
	h.seedMachine(issuesTestMachine, "u-alice")
	token := h.machineToken(issuesTestMachine, "u-alice")
	issue := h.seedOpenIssue()

	assertJSONError(t, h.do(issuesCall{method: http.MethodPost, path: "/v1/machine/issues/" + issue.ID + "/force-detach", bearer: token, body: map[string]any{"expectedStateRev": issue.StateRev}}), http.StatusNotFound, "not_found")
	assertJSONError(t, h.do(issuesCall{path: "/v1/machine/issues/" + issue.ID + "/claim", bearer: token}), http.StatusMethodNotAllowed, "method_not_allowed")
	assertJSONError(t, h.do(issuesCall{method: http.MethodPost, path: "/v1/machine/issues/" + issue.ID, bearer: token, body: map[string]any{}}), http.StatusMethodNotAllowed, "method_not_allowed")
	assertJSONError(t, h.do(issuesCall{method: http.MethodPost, path: "/v1/machine/teams", bearer: token}), http.StatusNotFound, "not_found")
	assertJSONError(t, h.do(issuesCall{method: http.MethodPost, path: "/v1/machine/issues/nope/claim", bearer: token, body: map[string]any{"claimId": "c", "expectedStateRev": 1}}), http.StatusNotFound, "not_found")
}

// ---- core: machine ownership seam (issues-core-claim-machine.test.ts) ----

func TestIssuesCoreMachineLookup(t *testing.T) {
	ctx := context.Background()
	alice := issuesPrincipal{UnionID: "u-alice", Name: "Alice"}
	active := func(mutate func(*store.MachineDoc)) func(context.Context, string) (store.MachineDoc, error) {
		doc := store.MachineDoc{ID: "m-alice", UnionID: "u-alice", OwnerName: "Alice", Status: store.MachineStatusActive}
		if mutate != nil {
			mutate(&doc)
		}
		return func(context.Context, string) (store.MachineDoc, error) { return doc, nil }
	}
	failing := func(err error) func(context.Context, string) (store.MachineDoc, error) {
		return func(context.Context, string) (store.MachineDoc, error) { return store.MachineDoc{}, err }
	}
	claim := func(h *issuesHarness, issue store.IssueDoc) issuesResponse {
		return h.a.issuesCoreClaim(ctx, issue.ID, alice, issuesClaimArgs{ClaimID: "c1", MachineID: "m-alice", ExpectedStateRev: float64(issue.StateRev)})
	}

	for name, tc := range map[string]struct {
		lookup func(context.Context, string) (store.MachineDoc, error)
		status int
		code   string
	}{
		"ACTIVE and owned":   {active(nil), http.StatusOK, ""},
		"missing":            {failing(store.ErrNotFound), http.StatusForbidden, "forbidden"},
		"owned by another":   {active(func(d *store.MachineDoc) { d.UnionID = "u-bob" }), http.StatusForbidden, "forbidden"},
		"RETIRED":            {active(func(d *store.MachineDoc) { d.Status = store.MachineStatusRetired }), http.StatusForbidden, "forbidden"},
		"store unavailable":  {failing(store.ErrUnavailable), http.StatusServiceUnavailable, "store_unavailable"},
		"other lookup error": {failing(errors.New("boom")), http.StatusServiceUnavailable, "store_unavailable"},
	} {
		t.Run("claim "+name, func(t *testing.T) {
			h := newIssuesHarness(t)
			h.a.Issues.LookupMachine = tc.lookup
			resp := claim(h, h.seedOpenIssue())
			if resp.status != tc.status {
				t.Fatalf("status = %d %+v, want %d", resp.status, resp.body, tc.status)
			}
			if tc.code != "" && resp.body != (issuesErrorBody{Error: tc.code}) {
				t.Fatalf("body = %+v, want %s", resp.body, tc.code)
			}
		})
	}

	// After a successful claim the machine is re-checked from claim.machineId
	// on bind and on a real status write.
	seedClaimed := func(t *testing.T) (*issuesHarness, store.IssueDoc) {
		h := newIssuesHarness(t)
		h.a.Issues.LookupMachine = active(nil)
		resp := claim(h, h.seedOpenIssue())
		if resp.status != http.StatusOK {
			t.Fatalf("claim = %+v", resp)
		}
		return h, resp.body.(issuesClaimBody).Issue
	}

	t.Run("bind after RETIRED is forbidden", func(t *testing.T) {
		h, issue := seedClaimed(t)
		h.a.Issues.LookupMachine = active(func(d *store.MachineDoc) { d.Status = store.MachineStatusRetired })
		resp := h.a.issuesCoreBind(ctx, issue.ID, alice, issuesBindArgs{ClaimID: "c1", LocalTaskRef: "local::t1", ExpectedStateRev: float64(issue.StateRev)})
		if resp.status != http.StatusForbidden || resp.body != (issuesErrorBody{Error: "forbidden"}) {
			t.Fatalf("bind = %+v", resp)
		}
	})

	t.Run("bind with the machine still ACTIVE succeeds", func(t *testing.T) {
		h, issue := seedClaimed(t)
		resp := h.a.issuesCoreBind(ctx, issue.ID, alice, issuesBindArgs{ClaimID: "c1", LocalTaskRef: "local::t1", ExpectedStateRev: float64(issue.StateRev)})
		if resp.status != http.StatusOK {
			t.Fatalf("bind = %+v", resp)
		}
	})

	t.Run("bind by someone other than the claimant is forbidden", func(t *testing.T) {
		h, issue := seedClaimed(t)
		h.addMember("u-bob")
		resp := h.a.issuesCoreBind(ctx, issue.ID, issuesPrincipal{UnionID: "u-bob"}, issuesBindArgs{ClaimID: "c1", LocalTaskRef: "x", ExpectedStateRev: float64(issue.StateRev)})
		if resp.status != http.StatusForbidden {
			t.Fatalf("bind = %+v", resp)
		}
	})

	status := func(h *issuesHarness, issue store.IssueDoc) issuesResponse {
		return h.a.issuesCoreStatus(ctx, issue.ID, alice, issuesStatusArgs{
			ClaimID: "c1", ClaimEpoch: float64(issue.Claim.ClaimEpoch), SourceSeq: 1, Status: store.IssueInProgress, ExpectedStateRev: float64(issue.StateRev),
		})
	}

	t.Run("status after an owner change is forbidden", func(t *testing.T) {
		h, issue := seedClaimed(t)
		h.a.Issues.LookupMachine = active(func(d *store.MachineDoc) { d.UnionID = "u-bob" })
		if resp := status(h, issue); resp.status != http.StatusForbidden {
			t.Fatalf("status = %+v", resp)
		}
	})

	t.Run("status with a valid machine succeeds", func(t *testing.T) {
		h, issue := seedClaimed(t)
		if resp := status(h, issue); resp.status != http.StatusOK {
			t.Fatalf("status = %+v", resp)
		}
	})
}

// ---- web entry ----

func TestWebIssuesAuthAndList(t *testing.T) {
	h := newIssuesHarness(t)
	alice := h.sessionCookie("u-alice")

	rec := h.do(issuesCall{path: "/api/issues?teamId=" + issuesTestTeam})
	if rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"unauthenticated"}` {
		t.Fatalf("anonymous = %d %s", rec.Code, rec.Body.String())
	}
	issuesExpect(t, h.do(issuesCall{path: "/api/issues", cookie: alice}), http.StatusBadRequest, "missing_teamId")
	issuesExpect(t, h.do(issuesCall{path: "/api/issues?teamId=", cookie: alice}), http.StatusBadRequest, "missing_teamId")
	issuesExpect(t, h.do(issuesCall{path: "/api/issues?teamId=" + issuesTestTeam, cookie: h.sessionCookie("u-carol")}), http.StatusNotFound, "not_found")

	rec = h.do(issuesCall{path: "/api/issues?teamId=" + issuesTestTeam, cookie: alice})
	if rec.Code != http.StatusOK || rec.Body.String() != `{"sections":{"needsAttention":[],"todo":[],"inProgress":[],"inReview":[],"done":[]}}` {
		t.Fatalf("empty list = %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "" {
		t.Fatalf("web list must not be no-store: %q", rec.Header().Get("Cache-Control"))
	}

	// URL parsing follows new URL(): '+' is a space, the first value wins.
	h.seedOpenIssue()
	body := issuesExpect(t, h.do(issuesCall{path: "/api/issues?teamId=" + issuesTestTeam + "&teamId=other", cookie: alice}), http.StatusOK, "")
	if todo := issuesPath(body, "sections", "todo").([]any); len(todo) != 1 {
		t.Fatalf("list = %v", body)
	}

	issuesExpect(t, h.do(issuesCall{path: "/api/issues/a/b", cookie: alice}), http.StatusNotFound, "not_found")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPut, path: "/api/issues", cookie: alice}), http.StatusNotFound, "not_found")
}

func TestWebIssuesCreate(t *testing.T) {
	h := newIssuesHarness(t)
	alice := h.sessionCookie("u-alice")
	create := func(body any, origin bool) *httptest.ResponseRecorder {
		return h.do(issuesCall{method: http.MethodPost, path: "/api/issues", cookie: alice, origin: origin, body: body})
	}

	issuesExpect(t, create(map[string]any{"teamId": issuesTestTeam, "title": "x"}, false), http.StatusForbidden, "bad_origin")
	issuesExpect(t, create(map[string]any{"teamId": issuesTestTeam, "title": ""}, true), http.StatusBadRequest, "invalid")
	issuesExpect(t, create(map[string]any{"title": "x"}, true), http.StatusBadRequest, "invalid")
	issuesExpect(t, create("not json", true), http.StatusBadRequest, "invalid")
	issuesExpect(t, create(map[string]any{"teamId": map[string]any{"$ne": ""}, "title": "x"}, true), http.StatusNotFound, "not_found")
	issuesExpect(t, create(map[string]any{"teamId": issuesTestTeam, "title": "x", "suggestedAssigneeUnionId": 5}, true), http.StatusBadRequest, "invalid")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: "/api/issues", cookie: h.sessionCookie("u-carol"), origin: true, body: map[string]any{"teamId": issuesTestTeam, "title": "nope"}}), http.StatusNotFound, "not_found")

	// Default form: body and repo are required, so a legacy title-only create
	// reports the first missing field.
	body := issuesExpect(t, create(map[string]any{"teamId": issuesTestTeam, "title": "only title"}, true), http.StatusBadRequest, "")
	if body["field"] == nil {
		t.Fatalf("field error = %v", body)
	}

	// A team form with a custom field: customFields / values feed it.
	if err := h.repo.UpdateTeamIssueSettings(context.Background(), issuesTestTeam, store.TeamIssueSettingsPatch{
		SetIssueForm: true,
		IssueForm: map[string]any{"fields": []any{
			map[string]any{"id": "title", "type": "text", "label": "Title", "required": true},
			map[string]any{"id": "body", "type": "textarea", "label": "Body", "required": false},
			map[string]any{"id": "repo", "type": "repo", "label": "Repo", "required": false, "allowCustom": true},
			map[string]any{"id": "sev", "type": "text", "label": "Sev", "required": false},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	rec := create(map[string]any{
		"teamId": issuesTestTeam, "title": "Parity issue", "body": "details", "labels": []string{"bug"},
		"targetRepoLabel": "platform", "customFields": map[string]any{"sev": "P1"},
	}, true)
	body = issuesExpect(t, rec, http.StatusCreated, "")
	issue := body["issue"].(map[string]any)
	if issue["title"] != "Parity issue" || issue["body"] != "details" || issue["status"] != "open" || issue["createdBy"] != "u-alice" ||
		issuesPath(issue, "customFields", "sev") != "P1" || issue["targetRepoLabel"] != "platform" {
		t.Fatalf("created = %s", rec.Body.String())
	}
	if !strings.HasPrefix(rec.Body.String(), `{"issue":{`) {
		t.Fatalf("body shape = %s", rec.Body.String())
	}

	rec = create(map[string]any{"teamId": issuesTestTeam, "values": map[string]any{"title": "Form issue", "body": "from form", "repo": map[string]any{"label": "web"}, "sev": "P0"}}, true)
	body = issuesExpect(t, rec, http.StatusCreated, "")
	if issuesPath(body, "issue", "title") != "Form issue" || issuesPath(body, "issue", "targetRepoLabel") != "web" || issuesPath(body, "issue", "customFields", "sev") != "P0" {
		t.Fatalf("values create = %s", rec.Body.String())
	}
}

func TestWebIssuesEventsPatchAndSensitiveWrites(t *testing.T) {
	h := newIssuesHarness(t)
	h.addMember("u-bob")
	alice, bob := h.sessionCookie("u-alice"), h.sessionCookie("u-bob")
	issue := h.seedOpenIssue()
	base := "/api/issues/" + issue.ID

	// events: after defaults to 0; Number(after) || 0.
	for _, query := range []string{"", "?after=0", "?after=abc", "?after=-0", "?after=%20"} {
		body := issuesExpect(t, h.do(issuesCall{path: base + "/events" + query, cookie: alice}), http.StatusOK, "")
		if events := body["events"].([]any); len(events) != 1 {
			t.Fatalf("events%s = %v", query, body)
		}
	}
	if body := issuesExpect(t, h.do(issuesCall{path: base + "/events?after=1", cookie: alice}), http.StatusOK, ""); len(body["events"].([]any)) != 0 {
		t.Fatalf("events after 1 = %v", body)
	}
	issuesExpect(t, h.do(issuesCall{path: base + "/events", cookie: h.sessionCookie("u-carol")}), http.StatusNotFound, "not_found")
	issuesExpect(t, h.do(issuesCall{path: "/api/issues/iss_000000000000000000000000/events", cookie: alice}), http.StatusNotFound, "not_found")
	issuesExpect(t, h.do(issuesCall{path: base, cookie: alice}), http.StatusMethodNotAllowed, "method_not_allowed")

	// PATCH
	issuesExpect(t, h.do(issuesCall{method: http.MethodPatch, path: base, cookie: alice, body: map[string]any{"rev": issue.Rev, "title": "x"}}), http.StatusForbidden, "bad_origin")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPatch, path: base, cookie: alice, origin: true, body: map[string]any{"title": "x"}}), http.StatusBadRequest, "missing_rev")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPatch, path: base, cookie: alice, origin: true, body: map[string]any{"rev": "1", "title": "x"}}), http.StatusBadRequest, "missing_rev")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPatch, path: base, cookie: alice, origin: true, body: map[string]any{"rev": issue.Rev, "labels": []any{"a", 1}}}), http.StatusBadRequest, "invalid")
	// TS throws on title.slice for a number → top-level 500 text.
	rec := h.do(issuesCall{method: http.MethodPatch, path: base, cookie: alice, origin: true, body: map[string]any{"rev": issue.Rev, "title": 5}})
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != "internal error" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("crash path = %d %q %q", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	body := issuesExpect(t, h.do(issuesCall{method: http.MethodPatch, path: base, cookie: alice, origin: true, body: map[string]any{"rev": issue.Rev, "title": "v2", "labels": []string{"bug", "p1"}, "targetRepoId": nil}}), http.StatusOK, "")
	if issuesPath(body, "issue", "title") != "v2" || issuesPath(body, "issue", "rev") != float64(issue.Rev+1) {
		t.Fatalf("patch = %v", body)
	}
	issuesExpect(t, h.do(issuesCall{method: http.MethodPatch, path: base, cookie: alice, origin: true, body: map[string]any{"rev": issue.Rev, "title": "stale"}}), http.StatusConflict, "rev_conflict")
	stateRev := issuesPath(body, "issue", "stateRev")

	// High-sensitivity writes need a fresh SSO login (10 min) before Origin.
	h.a.Issues.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	rec = h.do(issuesCall{method: http.MethodPost, path: base + "/force-detach", cookie: alice, body: map[string]any{"expectedStateRev": stateRev}})
	if rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"stale_session","loginUrl":"/auth/login"}` {
		t.Fatalf("stale = %d %s", rec.Code, rec.Body.String())
	}
	h.a.Issues.Now = nil
	issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: base + "/force-detach", cookie: alice, body: map[string]any{"expectedStateRev": stateRev}}), http.StatusForbidden, "bad_origin")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: base + "/force-detach", cookie: alice, origin: true, body: map[string]any{}}), http.StatusBadRequest, "missing_expectedStateRev")
	// Neither the issue creator nor a team admin.
	issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: base + "/force-detach", cookie: bob, origin: true, body: map[string]any{"expectedStateRev": stateRev}}), http.StatusForbidden, "forbidden")
	issuesExpect(t, h.do(issuesCall{method: http.MethodDelete, path: base, cookie: bob, origin: true}), http.StatusForbidden, "forbidden")

	rec = h.do(issuesCall{method: http.MethodPost, path: base + "/cancel", cookie: alice, origin: true, body: map[string]any{}})
	if rec.Code != http.StatusNotImplemented || rec.Body.String() != `{"error":"not_implemented","detail":"web cancel ships in P2"}` {
		t.Fatalf("cancel = %d %s", rec.Code, rec.Body.String())
	}
	issuesExpect(t, h.do(issuesCall{method: http.MethodPut, path: base, cookie: alice, origin: true, body: map[string]any{}}), http.StatusMethodNotAllowed, "method_not_allowed")

	body = issuesExpect(t, h.do(issuesCall{method: http.MethodDelete, path: base, cookie: alice, origin: true}), http.StatusOK, "")
	if issuesPath(body, "issue", "archivedAt") == nil {
		t.Fatalf("archive = %v", body)
	}
	list := issuesExpect(t, h.do(issuesCall{path: "/api/issues?teamId=" + issuesTestTeam, cookie: alice}), http.StatusOK, "")
	if todo := issuesPath(list, "sections", "todo").([]any); len(todo) != 0 {
		t.Fatalf("archived issue still listed: %v", list)
	}
}

func TestWebIssuesStoreUnavailable(t *testing.T) {
	h := newIssuesHarness(t)
	h.a.IssueStore = store.NewIssueStore(store.UnavailableDatabaseProvider{})
	issuesExpect(t, h.do(issuesCall{path: "/api/issues?teamId=" + issuesTestTeam, cookie: h.sessionCookie("u-alice")}), http.StatusServiceUnavailable, "store_unavailable")
}

// ---- team issue settings + admins ----

func TestTeamIssueSettingsAPI(t *testing.T) {
	h := newIssuesHarness(t)
	h.addMember("u-bob")
	alice, bob := h.sessionCookie("u-alice"), h.sessionCookie("u-bob")
	settings := "/api/teams/" + issuesTestTeam + "/issue-settings"
	admins := "/api/teams/" + issuesTestTeam + "/admins"

	for _, path := range []string{settings, admins} {
		rec := h.do(issuesCall{path: path})
		if rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"unauthenticated"}` {
			t.Fatalf("%s anonymous = %d %s", path, rec.Code, rec.Body.String())
		}
	}

	body := issuesExpect(t, h.do(issuesCall{path: settings, cookie: alice}), http.StatusOK, "")
	if body["teamId"] != issuesTestTeam || body["canEdit"] != true || body["createdBy"] != "u-alice" ||
		len(body["admins"].([]any)) != 0 || len(body["repoPresets"].([]any)) != 0 || len(issuesPath(body, "issueForm", "fields").([]any)) != 4 {
		t.Fatalf("settings = %v", body)
	}
	if body := issuesExpect(t, h.do(issuesCall{path: settings, cookie: bob}), http.StatusOK, ""); body["canEdit"] != false {
		t.Fatalf("member settings = %v", body)
	}
	issuesExpect(t, h.do(issuesCall{path: settings, cookie: h.sessionCookie("u-carol")}), http.StatusNotFound, "not_found")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: settings, cookie: alice, origin: true}), http.StatusMethodNotAllowed, "method_not_allowed")

	put := map[string]any{"repoPresets": []any{map[string]any{"id": "r1", "label": "platform"}}}
	issuesExpect(t, h.do(issuesCall{method: http.MethodPut, path: settings, cookie: alice, body: put}), http.StatusForbidden, "bad_origin")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPut, path: settings, cookie: bob, origin: true, body: put}), http.StatusForbidden, "not_admin")
	body = issuesExpect(t, h.do(issuesCall{method: http.MethodPut, path: settings, cookie: alice, origin: true, body: put}), http.StatusOK, "")
	presets := body["repoPresets"].([]any)
	if len(presets) != 1 || presets[0].(map[string]any)["label"] != "platform" || body["canEdit"] != true {
		t.Fatalf("put settings = %v", body)
	}

	// admins: PUT only, creator only; elements go through String().
	issuesExpect(t, h.do(issuesCall{path: admins, cookie: alice}), http.StatusMethodNotAllowed, "method_not_allowed")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPut, path: admins, cookie: alice, body: map[string]any{"admins": []string{"u-bob"}}}), http.StatusForbidden, "bad_origin")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPut, path: admins, cookie: alice, origin: true, body: map[string]any{"admins": "u-bob"}}), http.StatusBadRequest, "invalid")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPut, path: admins, cookie: bob, origin: true, body: map[string]any{"admins": []string{"u-bob"}}}), http.StatusForbidden, "not_creator")
	rec := h.do(issuesCall{method: http.MethodPut, path: admins, cookie: alice, origin: true, body: map[string]any{"admins": []string{"u-bob"}}})
	if rec.Code != http.StatusOK || rec.Body.String() != `{"teamId":"`+issuesTestTeam+`","createdBy":"u-alice","admins":["u-bob"]}` {
		t.Fatalf("put admins = %d %s", rec.Code, rec.Body.String())
	}
	// bob is an admin now: may edit settings and manage issues.
	if body := issuesExpect(t, h.do(issuesCall{path: settings, cookie: bob}), http.StatusOK, ""); body["canEdit"] != true {
		t.Fatalf("admin settings = %v", body)
	}

	// A path that is not ours falls through to the rest of the router.
	if handled := h.a.handleTeamIssueSettingsAPI(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/teams/"+issuesTestTeam+"/roster", nil)); handled {
		t.Fatal("foreign team path handled without a session")
	}
}

// ---- desktop entry ----

func TestDesktopIssuesAPI(t *testing.T) {
	h := newIssuesHarness(t)
	h.seedMachine(issuesTestMachine, "u-alice")
	token := h.desktopToken("u-alice")
	issue := h.seedOpenIssue()

	assertJSONError(t, h.do(issuesCall{path: "/v1/desktop/teams"}), http.StatusUnauthorized, "unauthenticated")
	rec := h.do(issuesCall{path: "/v1/desktop/teams", bearer: token})
	if rec.Code != http.StatusOK || rec.Body.String() != `{"teams":[{"teamId":"`+issuesTestTeam+`","teamName":"Team"}]}` || rec.Header().Get("Cache-Control") != "" {
		t.Fatalf("teams = %d %s", rec.Code, rec.Body.String())
	}
	issuesExpect(t, h.do(issuesCall{path: "/v1/desktop/issues", bearer: token}), http.StatusBadRequest, "missing_teamId")
	body := issuesExpect(t, h.do(issuesCall{path: "/v1/desktop/issues?teamId=" + issuesTestTeam, bearer: token}), http.StatusOK, "")
	if len(issuesPath(body, "sections", "todo").([]any)) != 1 {
		t.Fatalf("list = %v", body)
	}

	claimPath := "/v1/desktop/issues/" + issue.ID + "/claim"
	// The desktop must name the machine, and it must be the user's ACTIVE one.
	issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: claimPath, bearer: token, body: map[string]any{"claimId": "c1", "expectedStateRev": issue.StateRev}}), http.StatusBadRequest, "invalid")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: claimPath, bearer: token, body: map[string]any{"claimId": "c1", "machineId": 7, "expectedStateRev": issue.StateRev}}), http.StatusBadRequest, "invalid")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: claimPath, bearer: token, body: map[string]any{"claimId": "c1", "machineId": "deadbeefdeadbeef", "expectedStateRev": issue.StateRev}}), http.StatusForbidden, "forbidden")
	body = issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: claimPath, bearer: token, body: map[string]any{"claimId": "c1", "machineId": issuesTestMachine, "expectedStateRev": issue.StateRev}}), http.StatusOK, "")
	if issuesPath(body, "claim", "machineId") != issuesTestMachine {
		t.Fatalf("claim = %v", body)
	}
	// No machine fence on the desktop entry: the claimant may bind from any client.
	body = issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: "/v1/desktop/issues/" + issue.ID + "/bind", bearer: token, body: map[string]any{
		"claimId": "c1", "localTaskRef": "desk::1", "expectedStateRev": issuesPath(body, "issue", "stateRev"),
	}}), http.StatusOK, "")
	if issuesPath(body, "issue", "claim", "bound") != true {
		t.Fatalf("bind = %v", body)
	}

	issuesExpect(t, h.do(issuesCall{path: claimPath, bearer: token}), http.StatusMethodNotAllowed, "method_not_allowed")
	issuesExpect(t, h.do(issuesCall{method: http.MethodPost, path: "/v1/desktop/issues/" + issue.ID + "/force-detach", bearer: token, body: map[string]any{}}), http.StatusNotFound, "not_found")
}

// ---- request body parsing (JSON.parse semantics) ----

func TestIssuesParseJSONFollowsJSONParse(t *testing.T) {
	value, ok := issuesParseJSON([]byte(`{"b":1,"2":true,"a":{"x":null},"b":[1e400,"s"],"1":0,"-1":1,"01":2}`))
	if !ok {
		t.Fatal("parse failed")
	}
	obj := value.(*issueJSONObject)
	if got := strings.Join(obj.keys, ","); got != "1,2,b,a,-1,01" {
		t.Fatalf("keys = %s", got)
	}
	list := obj.values["b"].([]any)
	if f, ok := list[0].(float64); !ok || f <= 1e308 {
		t.Fatalf("1e400 = %v", list[0])
	}
	if inner := obj.values["a"].(*issueJSONObject); inner.values["x"] != nil || len(inner.keys) != 1 {
		t.Fatalf("nested = %+v", inner)
	}
	for _, bad := range []string{``, `{`, `{"a":1}x`, `{"a":1}{}`, `[1,]`, `nul`} {
		if _, ok := issuesParseJSON([]byte(bad)); ok {
			t.Errorf("parsed invalid JSON %q", bad)
		}
	}
	for _, good := range []string{`null`, `"x"`, `1`, `[]`, ` {} `} {
		if _, ok := issuesParseJSON([]byte(good)); !ok {
			t.Errorf("rejected %q", good)
		}
	}
}

func TestIssuesJSStringAndBSONValue(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{nil, "null"}, {true, "true"}, {1.5, "1.5"}, {1e21, "1e+21"}, {"s", "s"},
		{[]any{1.0, nil, "x", []any{2.0, 3.0}}, "1,,x,2,3"}, {&issueJSONObject{}, "[object Object]"},
	} {
		if got := issuesJSString(tc.in); got != tc.want {
			t.Errorf("issuesJSString(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	parsed, _ := issuesParseJSON([]byte(`{"i":3,"neg":-0,"big":3000000000,"f":1.5,"list":[1,2.5],"o":{"z":1,"a":2}}`))
	doc, ok := issuesBSONValue(parsed).(bson.D)
	if !ok {
		t.Fatalf("shape = %T", issuesBSONValue(parsed))
	}
	want := map[string]string{"i": "int32", "neg": "int32", "big": "float64", "f": "float64", "list": "primitive.A", "o": "primitive.D"}
	for _, e := range doc {
		if got := fmt.Sprintf("%T", e.Value); got != want[e.Key] {
			t.Errorf("%s = %s, want %s", e.Key, got, want[e.Key])
		}
	}
	list := doc[4].Value.(bson.A)
	if _, ok := list[0].(int32); !ok {
		t.Errorf("list[0] = %T", list[0])
	}
	if inner := doc[5].Value.(bson.D); inner[0].Key != "z" || inner[1].Key != "a" {
		t.Errorf("object order = %v", inner)
	}
}
