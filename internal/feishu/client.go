package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrTokenInvalid = errors.New("feishu: user token invalid")
	ErrUserNotFound = errors.New("feishu: user not found")
	// ErrFeishuNotConfigured mirrors the TypeScript `feishu_not_configured`
	// result of invite DMs and platform group creation.
	ErrFeishuNotConfigured = errors.New("feishu_not_configured")
	// ErrNotConfigured mirrors the TypeScript `not_configured` result of the
	// union_id-addressed DMs (also returned when the recipient is empty).
	ErrNotConfigured = errors.New("not_configured")
)

// APIError is a Feishu business failure (code !== 0). Code is -1 when the
// response carried no integer code (TypeScript treats a missing code as a
// failure too). Error() renders the same text the TypeScript client produces
// for that call site.
type APIError struct {
	Code int
	Msg  string
	text string
}

func (e *APIError) Error() string {
	if e.text != "" {
		return e.text
	}
	return fmt.Sprintf("feishu API error: code=%d msg=%s", e.Code, e.Msg)
}

// HTTPError is a response whose body is not JSON. Like `res.json()` in the
// TypeScript client, the HTTP status alone never fails a call: a JSON error
// body (e.g. 401 token expired) is parsed and handled by its code.
type HTTPError struct {
	Status int
	Body   string
	// raw is the untrimmed body (the TypeScript lark() msg uses text.slice).
	raw string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("feishu HTTP error: status=%d body=%s", e.Status, e.Body)
}

type Client struct {
	baseURL   string
	appID     string
	appSecret string
	http      *http.Client
	now       func() time.Time

	openIDMu sync.Mutex
	openIDs  map[string]string

	unionIDMu      sync.Mutex
	unionIDByEmail map[string]string

	tenantMu       sync.Mutex
	tenantToken    string
	tenantTokenExp time.Time
}

func NewClient(baseURL, appID, appSecret string, hc *http.Client) *Client {
	if baseURL == "" {
		baseURL = "https://open.feishu.cn"
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"), appID: appID, appSecret: appSecret, http: hc, now: time.Now,
		openIDs: make(map[string]string), unionIDByEmail: make(map[string]string),
	}
}

func (c *Client) Configured() bool { return c != nil && c.appID != "" && c.appSecret != "" }

const (
	// apiTimeout is the TypeScript fetch abort for oauth/contact/im calls;
	// group calls (`lark()`) use larkTimeout.
	apiTimeout  = 8 * time.Second
	larkTimeout = 10 * time.Second
	// codeMissing is the Code of a response without an integer `code`.
	codeMissing = -1
)

// envelope is a decoded Feishu JSON response. Fields are read leniently from
// the raw members so an unexpected type never fails the whole response.
type envelope struct {
	Code   int
	Msg    string
	Data   json.RawMessage
	fields map[string]json.RawMessage
}

func (e envelope) ok() bool { return e.Code == 0 }

// codeText is String(res.code) ("undefined" when absent).
func (e envelope) codeText() string { return jsString(e.fields["code"]) }

// msgText is String(res.msg); msgOrEmpty is `res.msg || ""`.
func (e envelope) msgText() string    { return jsString(e.fields["msg"]) }
func (e envelope) msgOrEmpty() string { return jsOrEmpty(e.fields["msg"]) }

func (e envelope) str(name string) string { return str(e.fields, name) }

// dataFields is `res?.data` as an object (nil when absent or not an object).
func (e envelope) dataFields() map[string]json.RawMessage { return objectFields(e.Data) }

// dataOrSelf is `res.data || res`.
func (e envelope) dataOrSelf() map[string]json.RawMessage {
	if truthy(e.Data) {
		if fields := objectFields(e.Data); fields != nil {
			return fields
		}
		// A truthy non-object data has no members.
		return map[string]json.RawMessage{}
	}
	return e.fields
}

func (e envelope) apiError(text string) *APIError {
	return &APIError{Code: e.Code, Msg: e.Msg, text: text}
}

func parseEnvelope(body []byte) (envelope, bool) {
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	if !json.Valid(body) {
		return envelope{}, false
	}
	// Non-object JSON (null, arrays, ...) has no members: code is missing.
	fields := objectFields(body)
	if fields == nil {
		fields = map[string]json.RawMessage{}
	}
	e := envelope{Code: codeMissing, fields: fields, Data: fields["data"]}
	if f, ok := numberValue(fields["code"]); ok && f == math.Trunc(f) && math.Abs(f) <= math.MaxInt32 {
		e.Code = int(f)
	}
	e.Msg, _ = stringValue(fields["msg"])
	return e, true
}

type callOptions struct {
	timeout time.Duration
	// alwaysContentType sends Content-Type even without a body (lark()).
	alwaysContentType bool
}

func (c *Client) doJSON(ctx context.Context, method, path, bearer string, body any) (envelope, error) {
	return c.do(ctx, method, path, bearer, body, callOptions{timeout: apiTimeout})
}

func (c *Client) do(ctx context.Context, method, path, bearer string, body any, opts callOptions) (result envelope, resultErr error) {
	started := time.Now()
	operation := feishuOperation(method, path)
	defer func() {
		if resultErr != nil && !errors.Is(resultErr, context.Canceled) {
			logFeishuFailure(operation, time.Since(started), resultErr)
		}
	}()
	if opts.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.timeout)
		defer cancel()
	}
	var payload io.Reader
	if body != nil {
		b, err := marshalJS(body)
		if err != nil {
			return envelope{}, err
		}
		payload = bytes.NewReader(b)
	}
	u := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		u = c.baseURL + path
	}
	req, err := http.NewRequestWithContext(ctx, method, u, payload)
	if err != nil {
		return envelope{}, err
	}
	if body != nil || opts.alwaysContentType {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return envelope{}, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return envelope{}, err
	}
	out, ok := parseEnvelope(b)
	if !ok {
		return envelope{}, &HTTPError{Status: res.StatusCode, Body: strings.TrimSpace(string(b)), raw: string(b)}
	}
	if !out.ok() {
		slog.Warn("runtime dependency failure", "dependency", "feishu", "operation", operation, "durationMs", time.Since(started).Milliseconds(), "apiCode", out.Code, "httpStatus", res.StatusCode)
	}
	return out, nil
}

// lark mirrors the TypeScript group helper: it never fails. Transport errors
// and non-JSON responses fold into code -1 (the latter with the HTTP status
// and the first 200 characters of the body as msg).
func (c *Client) lark(ctx context.Context, method, path, token string, body any) envelope {
	e, err := c.do(ctx, method, path, token, body, callOptions{timeout: larkTimeout, alwaysContentType: true})
	if err == nil {
		return e
	}
	msg := err.Error()
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		msg = fmt.Sprintf("HTTP %d: %s", httpErr.Status, sliceUTF16(httpErr.raw, 200))
	}
	msgJSON, _ := marshalJS(msg)
	return envelope{Code: -1, Msg: msg, fields: map[string]json.RawMessage{"code": json.RawMessage("-1"), "msg": msgJSON}}
}

func logFeishuFailure(operation string, duration time.Duration, err error) {
	attributes := []any{"dependency", "feishu", "operation", operation, "durationMs", duration.Milliseconds()}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		// Do not emit the response body: Feishu errors can contain user data and
		// the body is intentionally retained only for the caller's diagnosis.
		attributes = append(attributes, "httpStatus", httpErr.Status)
	} else {
		attributes = append(attributes, "error", err)
	}
	slog.Warn("runtime dependency failure", attributes...)
}

func feishuOperation(method, path string) string {
	endpoint := path
	if parsed, err := url.Parse(path); err == nil {
		endpoint = parsed.Path
	}
	if strings.HasPrefix(endpoint, "/open-apis/im/v1/chats/") {
		parts := strings.Split(strings.TrimPrefix(endpoint, "/open-apis/im/v1/chats/"), "/")
		endpoint = "/open-apis/im/v1/chats/:chat_id"
		if len(parts) > 1 && parts[1] != "" {
			endpoint += "/" + strings.Join(parts[1:], "/")
		}
	}
	if strings.HasPrefix(endpoint, "/open-apis/contact/v3/users/") && endpoint != "/open-apis/contact/v3/users/batch_get_id" {
		endpoint = "/open-apis/contact/v3/users/:user_id"
	}
	return strings.ToLower(method) + " " + endpoint
}

func requireOK(e envelope) error {
	if !e.ok() {
		return e.apiError("")
	}
	return nil
}
