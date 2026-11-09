package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const maxJSONBody = 64 << 10

func readJSON(r *http.Request, dst any) bool {
	if r.Body == nil {
		return false
	}
	defer r.Body.Close()
	reader := http.MaxBytesReader(nil, r.Body, maxJSONBody)
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(dst); err != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	// The TypeScript service writes JSON.stringify(value) verbatim. Encode into
	// a buffer first so the Go implementation neither appends Encoder's trailing
	// newline nor emits headers before a serialization error is known. Disabling
	// HTML escaping also keeps ordinary API strings compatible with
	// JSON.stringify (for example names containing '<' or '&').
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		text(w, http.StatusInternalServerError, "json encode failed")
		return
	}
	payload := unescapeLineSeparators(bytes.TrimSuffix(body.Bytes(), []byte{'\n'}))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// unescapeLineSeparators undoes encoding/json's unconditional \u2028 / \u2029
// escaping: JSON.stringify writes U+2028 and U+2029 raw, so a name containing
// them would otherwise differ byte-for-byte between the two backends. Escapes
// are walked in pairs, so an escaped backslash followed by "u2028" text is
// left alone.
func unescapeLineSeparators(payload []byte) []byte {
	if !bytes.Contains(payload, []byte(`\u202`)) {
		return payload
	}
	out := make([]byte, 0, len(payload))
	for i := 0; i < len(payload); i++ {
		if payload[i] != '\\' || i+1 >= len(payload) {
			out = append(out, payload[i])
			continue
		}
		if i+5 < len(payload) && payload[i+1] == 'u' && string(payload[i+2:i+5]) == "202" && (payload[i+5] == '8' || payload[i+5] == '9') {
			out = append(out, 0xE2, 0x80, 0xA8+(payload[i+5]-'8'))
			i += 5
			continue
		}
		out = append(out, payload[i], payload[i+1])
		i++
	}
	return out
}

func redirectWithCookie(w http.ResponseWriter, r *http.Request, target, cookie string) {
	_ = r // retained in the signature to keep call sites small
	if cookie != "" {
		w.Header().Add("Set-Cookie", cookie)
	}
	// http.Redirect synthesizes an HTML body and Content-Type. The legacy
	// redirect helper only sent status + Location (+ optional Set-Cookie).
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

// ServeDownload serves file as a public, uncached download (GET/HEAD only)
// with a SHA-256 ETag. Binaries take the digest from a "<file>.sha256"
// sidecar when one exists; shell scripts are served inline.
func ServeDownload(w http.ResponseWriter, r *http.Request, file, contentType, downloadName string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		text(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	stat, err := os.Stat(file)
	if err != nil || !stat.Mode().IsRegular() {
		text(w, http.StatusServiceUnavailable, "download unavailable")
		return
	}
	digest := ""
	if contentType == "application/octet-stream" {
		if checksum, err := os.ReadFile(file + ".sha256"); err == nil {
			candidate := strings.Fields(string(checksum))
			if len(candidate) > 0 && shaPattern.MatchString(candidate[0]) {
				digest = candidate[0]
			}
		}
	}
	if digest == "" {
		data, err := os.ReadFile(file)
		if err != nil {
			text(w, http.StatusServiceUnavailable, "download unavailable")
			return
		}
		sum := sha256.Sum256(data)
		digest = hex.EncodeToString(sum[:])
	}
	etag := `"` + digest + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", contentType)
	disposition := "attachment"
	if strings.HasPrefix(contentType, "text/x-shellscript") {
		disposition = "inline"
	}
	w.Header().Set("Content-Disposition", disposition+`; filename="`+downloadName+`"`)
	w.Header().Set("Content-Length", int64String(stat.Size()))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	handle, err := os.Open(file)
	if err != nil {
		return
	}
	defer handle.Close()
	_, _ = io.Copy(w, handle)
}

func serveIndex(w http.ResponseWriter, webDir string) {
	file := filepath.Join(webDir, "index.html")
	data, err := os.ReadFile(file)
	if err != nil {
		text(w, http.StatusInternalServerError, "前端文件缺失："+file)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func serveStatic(w http.ResponseWriter, webDir, requestPath string) bool {
	clean := filepath.Clean(strings.TrimLeft(requestPath, "/"))
	if clean == "." || clean == "" {
		return false
	}
	base, err := filepath.Abs(webDir)
	if err != nil {
		return false
	}
	file, err := filepath.Abs(filepath.Join(base, clean))
	if err != nil || (file != base && !strings.HasPrefix(file, base+string(filepath.Separator))) {
		return false
	}
	stat, err := os.Stat(file)
	if err != nil || !stat.Mode().IsRegular() {
		return false
	}
	contentType := staticContentTypes[strings.ToLower(filepath.Ext(file))]
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	if strings.Contains(file, string(filepath.Separator)+"assets"+string(filepath.Separator)) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	w.WriteHeader(http.StatusOK)
	handle, err := os.Open(file)
	if err == nil {
		defer handle.Close()
		_, _ = io.Copy(w, handle)
	}
	return true
}

func int64String(value int64) string {
	return strconv.FormatInt(value, 10)
}

var (
	shaPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	staticExtension = regexp.MustCompile(`\.[A-Za-z0-9]+$`)
)

// Keep these values independent of the host OS mime database. They mirror the
// previous TypeScript table, including source maps and the legacy icon type.
var staticContentTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".html":  "text/html; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".ico":   "image/x-icon",
	".webp":  "image/webp",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".map":   "application/json; charset=utf-8",
	".txt":   "text/plain; charset=utf-8",
}
