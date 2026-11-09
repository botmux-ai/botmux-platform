package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
)

type BotDirConfig struct {
	Mode       string  `json:"mode"`
	WorkingDir *string `json:"workingDir"`
}

type botDirCacheEntry struct {
	at      time.Time
	configs map[string]BotDirConfig
	ok      bool
	done    chan struct{}
}

type MachineAPI struct {
	cfg    config.Config
	client *http.Client
	mu     sync.Mutex
	cache  map[string]*botDirCacheEntry
}

const (
	machineAPITimeout        = 6 * time.Second
	dashboardHealthTimeout   = 9 * time.Second
	machineUpgradeRunTimeout = 190 * time.Second
)

func NewMachineAPI(cfg config.Config) *MachineAPI {
	// Individual operations own their timeout budget. A global Client.Timeout
	// would silently cap the 9s dashboard health check and 190s updater while
	// waiting for response headers or reading their bodies.
	// Node's fetch does not inherit HTTP_PROXY. Keep these authenticated calls
	// direct as well: they intentionally re-enter this service through its
	// machine subdomain, and routing them through a process-wide proxy can leak
	// the signed session cookie or bypass the platform's own ingress path.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &MachineAPI{cfg: cfg, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, cache: make(map[string]*botDirCacheEntry)}
}

func (m *MachineAPI) request(ctx context.Context, machineID, ownerID, method, path string, body any) (*http.Response, error) {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, MachineBaseURL(m.cfg, machineID)+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Cookie", auth.ProxySessionRequestCookie(m.cfg, auth.ProxyIdentity{UnionID: ownerID, MachineID: machineID}))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return m.client.Do(request)
}

// SetWorkingDir relays PUT /api/bots/:appId/working-dir-mode to the machine
// dashboard. The dashboard body is passed through with JSON.stringify
// fidelity; a non-JSON answer (the proxy's 503 reconnect page while the
// machine is offline) or a transport failure is 502 machine_unreachable.
func (m *MachineAPI) SetWorkingDir(ctx context.Context, machineID, ownerID, appID, mode, workingDir string) (int, JSValue) {
	requestCtx, cancel := context.WithTimeout(ctx, machineAPITimeout)
	defer cancel()
	unreachable := okErrorValue("machine_unreachable")
	response, err := m.request(requestCtx, machineID, ownerID, http.MethodPut, "/api/bots/"+encodeURIComponentJS(appID)+"/working-dir-mode", map[string]any{"mode": mode, "workingDir": workingDir})
	if err != nil {
		return http.StatusBadGateway, unreachable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return http.StatusBadGateway, unreachable
	}
	// res.json() strips a UTF-8 BOM and rejects an empty body.
	body, err := ParseJSValue(bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF")))
	if err != nil {
		return http.StatusBadGateway, unreachable
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		m.mu.Lock()
		delete(m.cache, machineID)
		m.mu.Unlock()
	}
	return response.StatusCode, body
}

// CheckDashboardHealth probes the authenticated machine subdomain, exercising
// the same proxy, cross-pod forwarding, and tunnel stream path as a browser.
func (m *MachineAPI) CheckDashboardHealth(ctx context.Context, machineID, ownerID string) bool {
	requestCtx, cancel := context.WithTimeout(ctx, dashboardHealthTimeout)
	defer cancel()
	response, err := m.request(requestCtx, machineID, ownerID, http.MethodGet, "/__health", nil)
	if err != nil {
		return false
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return readErr == nil && response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices
}

// UpgradeMachine installs the latest Botmux release, then asks the dashboard
// to restart only after a successful update. Its error shapes intentionally
// match the Node implementation consumed by the platform frontend, and the
// update body is relayed with JSON.stringify fidelity ({...update, ...}
// keeps the daemon's key order).
func (m *MachineAPI) UpgradeMachine(ctx context.Context, machineID, ownerID string) (int, JSValue) {
	updateCtx, cancelUpdate := context.WithTimeout(ctx, machineUpgradeRunTimeout)
	updateResponse, err := m.request(updateCtx, machineID, ownerID, http.MethodPost, "/api/update/run", nil)
	if err != nil {
		cancelUpdate()
		return http.StatusBadGateway, okErrorValue("machine_unreachable")
	}
	if updateResponse.StatusCode == http.StatusNotFound {
		_ = updateResponse.Body.Close()
		cancelUpdate()
		return http.StatusBadRequest, okErrorValue("upgrade_not_supported")
	}
	raw, readErr := io.ReadAll(io.LimitReader(updateResponse.Body, maxDashboardJSONBody+1))
	_ = updateResponse.Body.Close()
	cancelUpdate()
	updateOK := updateResponse.StatusCode >= http.StatusOK && updateResponse.StatusCode < http.StatusMultipleChoices
	var update JSValue
	if readErr == nil && len(raw) <= maxDashboardJSONBody {
		// res.json() strips a UTF-8 BOM and rejects an empty body.
		update, readErr = ParseJSValue(bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF")))
	} else if readErr == nil {
		readErr = io.ErrShortBuffer
	}
	if readErr != nil {
		if updateOK {
			return http.StatusBadRequest, okErrorValue("upgrade_not_supported")
		}
		return http.StatusBadGateway, okErrorValue("machine_unreachable")
	}
	if !updateOK || update.field("ok") == false {
		return updateResponse.StatusCode, update
	}
	// `{update: {oldVersion: update.oldVersion, newVersion: update.newVersion}}`;
	// reading a property of a null body throws, which TS reports as a failed
	// restart.
	if update.value == nil {
		return restartFailed(update)
	}
	version := &jsObject{values: map[string]any{}}
	for _, key := range []string{"oldVersion", "newVersion"} {
		if value, ok := update.lookup(key); ok {
			version.set(key, value)
		}
	}
	restartBody := JSValue{value: &jsObject{keys: []string{"update"}, values: map[string]any{"update": version}}}
	restartCtx, cancelRestart := context.WithTimeout(ctx, machineAPITimeout)
	defer cancelRestart()
	restartResponse, restartErr := m.request(restartCtx, machineID, ownerID, http.MethodPost, "/api/update/restart", restartBody)
	if restartErr != nil {
		return restartFailed(update)
	}
	_ = restartResponse.Body.Close()
	if restartResponse.StatusCode < http.StatusOK || restartResponse.StatusCode >= http.StatusMultipleChoices {
		return restartFailed(update)
	}
	result := update.spread()
	result.set("restarting", true)
	return http.StatusOK, JSValue{value: result}
}

func (m *MachineAPI) GetBotDirs(ctx context.Context, machineID, ownerID string, wait time.Duration) map[string]BotDirConfig {
	m.mu.Lock()
	entry := m.cache[machineID]
	now := time.Now()
	if entry != nil {
		ttl := 15 * time.Second
		if entry.ok {
			ttl = 45 * time.Second
		}
		if entry.done == nil && now.Sub(entry.at) < ttl {
			configs := cloneDirConfigs(entry.configs)
			m.mu.Unlock()
			return configs
		}
	}
	if entry == nil || entry.done == nil {
		old := entry
		entry = &botDirCacheEntry{done: make(chan struct{})}
		if old != nil {
			entry.at, entry.ok, entry.configs = old.at, old.ok, old.configs
		}
		m.cache[machineID] = entry
		go m.fetchBotDirs(machineID, ownerID, entry)
	}
	done := entry.done
	stale := cloneDirConfigs(entry.configs)
	m.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-done:
		m.mu.Lock()
		// A successful SetWorkingDir may invalidate the cache between fetch
		// completion and this waiter being scheduled. Fall back to the completed
		// entry instead of dereferencing a now-missing map entry.
		currentEntry := m.cache[machineID]
		if currentEntry == nil {
			currentEntry = entry
		}
		current := cloneDirConfigs(currentEntry.configs)
		m.mu.Unlock()
		return current
	case <-timer.C:
		return stale
	case <-ctx.Done():
		return stale
	}
}

func (m *MachineAPI) fetchBotDirs(machineID, ownerID string, entry *botDirCacheEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), machineAPITimeout)
	defer cancel()
	configs := map[string]BotDirConfig(nil)
	response, err := m.request(ctx, machineID, ownerID, http.MethodGet, "/api/bots", nil)
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			var payload struct {
				Bots []struct {
					LarkAppID         string `json:"larkAppId"`
					Error             any    `json:"error"`
					DefaultWorkingDir string `json:"defaultWorkingDir"`
					DefaultOncall     struct {
						Enabled    bool   `json:"enabled"`
						WorkingDir string `json:"workingDir"`
					} `json:"defaultOncall"`
				} `json:"bots"`
			}
			if json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&payload) == nil {
				configs = make(map[string]BotDirConfig)
				for _, bot := range payload.Bots {
					if bot.LarkAppID == "" || bot.Error != nil {
						continue
					}
					cfg := BotDirConfig{Mode: "off"}
					if bot.DefaultOncall.Enabled {
						cfg.Mode = "oncall"
						// The dashboard may omit workingDir for an enabled oncall
						// configuration. TypeScript maps that to null, not "".
						if bot.DefaultOncall.WorkingDir != "" {
							dir := bot.DefaultOncall.WorkingDir
							cfg.WorkingDir = &dir
						}
					} else if bot.DefaultWorkingDir != "" {
						cfg.Mode = "default"
						dir := bot.DefaultWorkingDir
						cfg.WorkingDir = &dir
					}
					configs[bot.LarkAppID] = cfg
				}
			}
		}
	}
	m.mu.Lock()
	// Always complete this entry and wake its waiters. Cache invalidation may
	// have removed it while the request was in flight; in that case the result
	// stays uncached, but callers already waiting on this fetch must not be left
	// blocked until their timeout.
	entry.configs = configs
	entry.ok = configs != nil
	entry.at = time.Now()
	done := entry.done
	entry.done = nil
	if done != nil {
		close(done)
	}
	m.mu.Unlock()
}

// okErrorValue is `{ ok: false, error: code }`.
func okErrorValue(code string) JSValue {
	return JSValue{value: &jsObject{keys: []string{"ok", "error"}, values: map[string]any{"ok": false, "error": code}}}
}

// restartFailed is `{ ...update, ok: false, error: 'restart_failed',
// updateInstalled: true }` with status 502.
func restartFailed(update JSValue) (int, JSValue) {
	result := update.spread()
	result.set("ok", false)
	result.set("error", "restart_failed")
	result.set("updateInstalled", true)
	return http.StatusBadGateway, JSValue{value: result}
}

func cloneDirConfigs(source map[string]BotDirConfig) map[string]BotDirConfig {
	if source == nil {
		return nil
	}
	out := make(map[string]BotDirConfig, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

// MachineDashboardJSON is one dashboard JSON read relayed to a client: the
// upstream status and its body re-encoded with JSON.stringify semantics.
type MachineDashboardJSON struct {
	Status int
	Body   JSValue
}

// maxDashboardJSONBody bounds a relayed dashboard body. The TS bridge reads
// res.text() unbounded; a cap keeps one misbehaving daemon from exhausting
// pod memory, and an over-limit body is reported as a transport failure.
const maxDashboardJSONBody = 8 << 20

// FetchMachineSessions reads every botmux session of a machine live (no
// platform cache) through the owner-cookie machine subdomain path. Keeping
// this server-side means the native app never receives a dashboard token.
func (m *MachineAPI) FetchMachineSessions(ctx context.Context, machineID, ownerID string) MachineDashboardJSON {
	return m.machineJSON(ctx, machineID, ownerID, "/api/sessions")
}

// FetchMachineSessionWriteLink reads the dashboard's current write-link of
// one session (used to tell machine terminals from external ones).
func (m *MachineAPI) FetchMachineSessionWriteLink(ctx context.Context, machineID, ownerID, sessionID string) MachineDashboardJSON {
	return m.machineJSON(ctx, machineID, ownerID, "/api/sessions/"+encodeURIComponentJS(sessionID)+"/write-link")
}

// machineJSON is the TS machineJson: transport failure is 502
// machine_unreachable; an unparsable body is 502 invalid_dashboard_response
// on a 2xx and the upstream status with machine_unreachable otherwise; an
// empty body is {}.
func (m *MachineAPI) machineJSON(ctx context.Context, machineID, ownerID, path string) MachineDashboardJSON {
	requestCtx, cancel := context.WithTimeout(ctx, machineAPITimeout)
	defer cancel()
	response, err := m.request(requestCtx, machineID, ownerID, http.MethodGet, path, nil)
	if err != nil {
		return MachineDashboardJSON{Status: http.StatusBadGateway, Body: jsErrorValue("machine_unreachable")}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxDashboardJSONBody+1))
	if err != nil || len(raw) > maxDashboardJSONBody {
		return MachineDashboardJSON{Status: http.StatusBadGateway, Body: jsErrorValue("machine_unreachable")}
	}
	// res.text() decodes UTF-8 and drops a leading BOM before JSON.parse.
	raw = bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF"))
	if len(raw) == 0 {
		return MachineDashboardJSON{Status: response.StatusCode, Body: JSValue{value: &jsObject{}}}
	}
	value, err := ParseJSValue(raw)
	if err != nil {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return MachineDashboardJSON{Status: http.StatusBadGateway, Body: jsErrorValue("invalid_dashboard_response")}
		}
		return MachineDashboardJSON{Status: response.StatusCode, Body: jsErrorValue("machine_unreachable")}
	}
	return MachineDashboardJSON{Status: response.StatusCode, Body: value}
}

// JSValue is a JSON value decoded with JSON.parse semantics and encoded with
// JSON.stringify semantics. Relaying a dashboard body through it reproduces
// the TS bridge's JSON.stringify(JSON.parse(text)) byte for byte: upstream key
// order (with integer-like keys first, as JS objects order them), last-wins
// duplicate keys, and JS number formatting (1.50 -> 1.5, 1e400 -> null).
type JSValue struct{ value any }

// jsObject keeps insertion order; values hold nil, bool, float64, string,
// []any or *jsObject.
type jsObject struct {
	keys   []string
	values map[string]any
}

var errJSValueTrailing = errors.New("trailing data after JSON value")

// ParseJSValue parses one JSON document the way JSON.parse does.
func ParseJSValue(raw []byte) (JSValue, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeJSValue(decoder)
	if err != nil {
		return JSValue{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return JSValue{}, errJSValueTrailing
	}
	return JSValue{value: value}, nil
}

// MarshalJSON emits the JSON.stringify bytes.
func (v JSValue) MarshalJSON() ([]byte, error) {
	return appendJSValue(nil, v.value), nil
}

// StringField returns obj[key] when the value is an object whose key holds a
// string (`typeof body?.[key] === 'string'`).
func (v JSValue) StringField(key string) (string, bool) {
	object, ok := v.value.(*jsObject)
	if !ok {
		return "", false
	}
	value, ok := object.values[key].(string)
	return value, ok
}

// field is `value[key]` for an object value (nil when absent or not an
// object; only meaningful for comparisons against non-nil literals).
func (v JSValue) field(key string) any {
	value, _ := v.lookup(key)
	return value
}

// lookup reports an object member; JSON.parse never yields undefined, so a
// present key always serializes.
func (v JSValue) lookup(key string) (any, bool) {
	object, ok := v.value.(*jsObject)
	if !ok {
		return nil, false
	}
	value, ok := object.values[key]
	return value, ok
}

// spread is `{ ...value }`: an object's own keys in order, an array's
// indexes; other primitives contribute nothing. (A string would spread its
// UTF-16 code units; a daemon never answers with a bare string.)
func (v JSValue) spread() *jsObject {
	out := &jsObject{values: map[string]any{}}
	switch value := v.value.(type) {
	case *jsObject:
		for _, key := range value.orderedKeys() {
			out.set(key, value.values[key])
		}
	case []any:
		for index, element := range value {
			out.set(strconv.Itoa(index), element)
		}
	}
	return out
}

// set is an ordinary property assignment: an existing key keeps its position.
func (o *jsObject) set(key string, value any) {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func jsErrorValue(code string) JSValue {
	return JSValue{value: &jsObject{keys: []string{"error"}, values: map[string]any{"error": code}}}
}

func decodeJSValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := &jsObject{values: map[string]any{}}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errJSValueTrailing
				}
				member, err := decodeJSValue(decoder)
				if err != nil {
					return nil, err
				}
				if _, exists := object.values[key]; !exists {
					object.keys = append(object.keys, key)
				}
				object.values[key] = member
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				element, err := decodeJSValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, element)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return array, nil
		}
		return nil, errJSValueTrailing
	case json.Number:
		// Out-of-range literals become ±Infinity (or 0) like Number(); the
		// ErrRange result value is exactly that.
		number, _ := strconv.ParseFloat(string(value), 64)
		return number, nil
	default:
		return value, nil
	}
}

func appendJSValue(dst []byte, value any) []byte {
	switch v := value.(type) {
	case nil:
		return append(dst, "null"...)
	case bool:
		return strconv.AppendBool(dst, v)
	case float64:
		return append(dst, jsNumberText(v)...)
	case string:
		return appendJSString(dst, v)
	case []any:
		dst = append(dst, '[')
		for i, element := range v {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSValue(dst, element)
		}
		return append(dst, ']')
	case *jsObject:
		dst = append(dst, '{')
		for i, key := range v.orderedKeys() {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSString(dst, key)
			dst = append(dst, ':')
			dst = appendJSValue(dst, v.values[key])
		}
		return append(dst, '}')
	}
	return append(dst, "null"...)
}

// orderedKeys is OrdinaryOwnPropertyKeys: array-index keys ascending, then
// the remaining string keys in insertion order.
func (o *jsObject) orderedKeys() []string {
	indexes := make([]string, 0)
	names := make([]string, 0, len(o.keys))
	for _, key := range o.keys {
		if isJSArrayIndex(key) {
			indexes = append(indexes, key)
		} else {
			names = append(names, key)
		}
	}
	if len(indexes) == 0 {
		return names
	}
	sort.Slice(indexes, func(i, j int) bool {
		if len(indexes[i]) != len(indexes[j]) {
			return len(indexes[i]) < len(indexes[j])
		}
		return indexes[i] < indexes[j]
	})
	return append(indexes, names...)
}

func isJSArrayIndex(key string) bool {
	if key == "0" {
		return true
	}
	if key == "" || len(key) > 10 || key[0] < '1' || key[0] > '9' {
		return false
	}
	for i := 1; i < len(key); i++ {
		if key[i] < '0' || key[i] > '9' {
			return false
		}
	}
	number, err := strconv.ParseUint(key, 10, 64)
	return err == nil && number < 4294967295
}

// appendJSString escapes like JSON.stringify: quote, backslash and C0
// controls only; HTML characters and U+2028/U+2029 stay literal.
func appendJSString(dst []byte, value string) []byte {
	const lowerHex = "0123456789abcdef"
	dst = append(dst, '"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			dst = append(dst, '\\', byte(r))
		case '\b':
			dst = append(dst, `\b`...)
		case '\f':
			dst = append(dst, `\f`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\r':
			dst = append(dst, `\r`...)
		case '\t':
			dst = append(dst, `\t`...)
		default:
			if r < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', lowerHex[r>>4], lowerHex[r&0xF])
			} else {
				dst = utf8.AppendRune(dst, r)
			}
		}
	}
	return append(dst, '"')
}

// jsNumberText is Number#toString as used by JSON.stringify (non-finite
// values become null, -0 becomes 0).
func jsNumberText(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "null"
	}
	if value == 0 {
		return "0"
	}
	if value < 0 {
		return "-" + jsNumberText(-value)
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(value, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	k := len(digits)
	power, _ := strconv.Atoi(exponent)
	n := power + 1 // value = digits × 10^(n−k)
	switch {
	case k <= n && n <= 21:
		return digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return "0." + strings.Repeat("0", -n) + digits
	}
	sign, magnitude := "+", n-1
	if magnitude < 0 {
		sign, magnitude = "-", -magnitude
	}
	if k == 1 {
		return digits + "e" + sign + strconv.Itoa(magnitude)
	}
	return digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(magnitude)
}
