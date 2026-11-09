package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMarkRelayedStatusWithoutMarkerIsNoop(t *testing.T) {
	MarkRelayedStatus(context.Background(), 500)
	MarkRelayedStatus(nil, 500) //nolint:staticcheck // nil context must not panic
	var m *RelayMarker
	if m.Status() != 0 {
		t.Fatal("nil marker must report 0")
	}
}

func TestCopyUpstreamResponseMarksRelayedStatus(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"daemon"}`)
	}))
	defer upstream.Close()

	ctx, marker := WithRelayMarker(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL+"/webhook/x", nil)
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	(&Dashboard{}).writeResponse(recorder, response)
	if recorder.Code != http.StatusInternalServerError || marker.Status() != http.StatusInternalServerError {
		t.Fatalf("status=%d marker=%d", recorder.Code, marker.Status())
	}
}

func TestPlatformWrittenErrorsAreNotMarked(t *testing.T) {
	ctx, marker := WithRelayMarker(context.Background())
	request := httptest.NewRequest(http.MethodGet, "http://m-x.example/", nil).WithContext(ctx)

	// Failed round trip: the platform answers 502 itself.
	recorder := httptest.NewRecorder()
	writeProxyError(recorder, "反代失败", errors.New("dial: refused"))
	if recorder.Code != http.StatusBadGateway || marker.Status() != 0 {
		t.Fatalf("proxy error: status=%d marker=%d", recorder.Code, marker.Status())
	}

	// An upstream response without a status is rewritten to 502 and not marked.
	recorder = httptest.NewRecorder()
	copyUpstreamResponse(recorder, &http.Response{StatusCode: 0, Header: http.Header{}, Body: http.NoBody, Request: request}, false)
	if recorder.Code != http.StatusBadGateway || marker.Status() != 0 {
		t.Fatalf("status 0: status=%d marker=%d", recorder.Code, marker.Status())
	}

	// Cross-pod forward to an unreachable peer: platform 502, not marked.
	recorder = httptest.NewRecorder()
	if err := forwardHTTP(ctx, "127.0.0.1:1", recorder, request); err == nil {
		t.Fatal("forward to a closed port should fail")
	}
	if recorder.Code != http.StatusBadGateway || marker.Status() != 0 {
		t.Fatalf("peer failure: status=%d marker=%d", recorder.Code, marker.Status())
	}
}
