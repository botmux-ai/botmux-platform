package runner

import (
	"context"
	"net/http"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/adaptor"
)

// hertzHeadHandler preserves the representation Content-Length required by
// RFC 9110 HEAD responses. The upstream net/http adaptor currently forces it
// to zero before writing the header, even when the application supplied the
// exact GET length. HEAD cannot hijack or stream, so a small response capture
// is sufficient and leaves all other methods on the upstream adaptor.
func hertzHeadHandler(handler http.Handler) app.HandlerFunc {
	return func(ctx context.Context, rc *app.RequestContext) {
		req, err := adaptor.GetCompatRequest(&rc.Request)
		if err != nil {
			rc.SetStatusCode(http.StatusInternalServerError)
			return
		}
		req = req.WithContext(ctx)
		req.Method = http.MethodHead
		req.Host = string(rc.Request.Host())
		req.RequestURI = string(rc.Request.RequestURI())
		req.RemoteAddr = rc.RemoteAddr().String()

		recorder := newHeadResponseCapture()
		handler.ServeHTTP(recorder, req)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		for name, values := range recorder.Header() {
			for _, value := range values {
				rc.Response.Header.Add(name, value)
			}
		}
		if recorder.Header().Get("Content-Length") == "" && recorder.written > 0 {
			rc.Response.Header.Set("Content-Length", strconv.FormatInt(recorder.written, 10))
		}
		rc.Response.Header.SetStatusCode(status)
		rc.Response.SkipBody = true
	}
}

type headResponseCapture struct {
	header  http.Header
	status  int
	written int64
}

func newHeadResponseCapture() *headResponseCapture {
	return &headResponseCapture{header: make(http.Header)}
}

func (w *headResponseCapture) Header() http.Header { return w.header }

func (w *headResponseCapture) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *headResponseCapture) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.written += int64(len(body))
	return len(body), nil
}

func (w *headResponseCapture) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
}

var _ http.Flusher = (*headResponseCapture)(nil)
