package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestRequestLog_UsesRoutePatternNotRawPath(t *testing.T) {
	var buf bytes.Buffer
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, req)
			writeRequestLog(&buf, req, sw.status, 12*time.Millisecond)
		})
	})
	r.Get("/v1/sessions/{sessionId}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/sessions/SECRET-SESSION-ID?token=SECRET-TOKEN", nil)
	req.Header.Set("X-Cloud-Trace-Context", "abc123/456;o=1")
	r.ServeHTTP(httptest.NewRecorder(), req)

	line := buf.String()
	if strings.Contains(line, "SECRET") {
		t.Fatalf("request log leaks a bearer value: %s", line)
	}
	var e requestLogEntry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("not one JSON line: %v\n%s", err, line)
	}
	if e.HTTPRequest.RequestURL != "/v1/sessions/{sessionId}" || e.HTTPRequest.Status != 404 {
		t.Fatalf("httpRequest = %+v", e.HTTPRequest)
	}
	if e.Severity != "WARNING" || e.Trace != "abc123" {
		t.Fatalf("severity/trace = %q/%q", e.Severity, e.Trace)
	}
}

func TestRequestLog_UnmatchedPathIsNotLogged(t *testing.T) {
	var buf bytes.Buffer
	req := httptest.NewRequest(http.MethodGet, "/whatever/attacker-chosen", nil)
	writeRequestLog(&buf, req, http.StatusInternalServerError, time.Millisecond)
	if strings.Contains(buf.String(), "attacker-chosen") || !strings.Contains(buf.String(), `"ERROR"`) {
		t.Fatalf("got %s", buf.String())
	}
}

func TestBuildDependencies_ReportsLogOnlySMS(t *testing.T) {
	t.Setenv("TWILIO_ACCOUNT_SID", "")
	deps, err := BuildDependencies("http://localhost/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if deps.SMSSenderKind != SMSDeliveryLog {
		t.Fatalf("SMSSenderKind = %q, want %q", deps.SMSSenderKind, SMSDeliveryLog)
	}
}
