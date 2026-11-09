package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/proxy"
)

func TestOpenAPIProxyMarksOnlyDaemonStatus(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	path := "/openapi/machines/" + openAPIMIDAlice + "/proxy/api/sessions"
	serve := func() (int, int) {
		ctx, marker := proxy.WithRelayMarker(context.Background())
		request := httptest.NewRequest(http.MethodGet, "http://localhost"+path, nil).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer tok")
		recorder := httptest.NewRecorder()
		h.apex.ServeHTTP(recorder, request)
		return recorder.Code, marker.Status()
	}

	h.apex.OpenAPI.ProxyFetch = h.recordingFetch(http.StatusInternalServerError, http.Header{"Content-Type": {"application/json"}}, `{"error":"daemon"}`)
	if status, marked := serve(); status != http.StatusInternalServerError || marked != http.StatusInternalServerError {
		t.Fatalf("daemon 500: status=%d marked=%d", status, marked)
	}

	h.apex.OpenAPI.ProxyFetch = func(context.Context, OpenAPIProxyRequest) (OpenAPIProxyResponse, error) {
		return OpenAPIProxyResponse{}, errors.New("machine offline")
	}
	if status, marked := serve(); status != http.StatusBadGateway || marked != 0 {
		t.Fatalf("unreachable: status=%d marked=%d", status, marked)
	}
}
