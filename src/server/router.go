package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Router builds the http.Handler that drives the server. The returned router
// is fresh on every call; tests typically call this once and pass it to
// httptest.NewServer.
//
// Route map (kept in sync with README.md):
//
//	GET  /healthz  (and /health alias)         — liveness probe
//	GET  /.well-known/did.json                 — issuer DID document
//	GET  /v1/config                            — public deployment config
//	GET  /v1/methods                           — list registered methods
//	POST /enrollment/start                     — create a session
//	GET  /v1/sessions/{sessionId}              — poll session progress
//	POST /v1/methods/{methodId}/begin          — start a method ceremony
//	POST /v1/methods/{methodId}/complete       — submit ceremony response
//	GET  /v1/methods/email/verify              — magic-link landing
//	POST /v1/credentials/issue                 — issue the W3C VC
//	GET  /v1/status-list/{listId}              — public revocation list
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(requestLogger)
	r.Use(s.corsMiddleware)
	r.Use(recoverer)
	r.Use(limitBody)
	if s.cfg.RateLimit.Enabled {
		r.Use(newRateLimiter(s.cfg.RateLimit, nil).middleware)
	}

	r.Get("/healthz", s.handleHealth)
	// /health is an alias: Google's frontend intercepts /healthz on *.run.app
	// and answers its own 404 before the request reaches the container (every
	// other route gets through), so Cloud Run deployments must probe /health.
	r.Get("/health", s.handleHealth)
	r.Get("/.well-known/did.json", s.handleDIDDocument)

	r.Route("/v1", func(r chi.Router) {
		// Public and unauthenticated, like /v1/methods: it advertises only
		// which gates exist, never the invite code itself. The web app reads
		// it before /enrollment/start to decide whether to prompt for a code.
		r.Get("/config", s.handleConfig)
		r.Get("/methods", s.handleListMethods)
		r.Get("/sessions/{sessionId}", s.handleGetSession)

		r.Route("/methods/{methodId}", func(r chi.Router) {
			r.Post("/begin", s.handleBeginMethod)
			r.Post("/complete", s.handleCompleteMethod)
		})

		// Explicit landing route for the email magic link. Kept under /v1
		// so a single base URL covers every public route the server emits.
		r.Get("/methods/email/verify", s.handleEmailMagicLink)

		r.Post("/credentials/issue", s.handleIssueCredential)
		r.Get("/status-list/{listId}", s.handleStatusList)

		// Method-owned routes (e.g. third-party webhook receivers). Mounted
		// under /v1/methods/{id}/{path}. Added at build time by
		// BuildDependencies; see government-id-liveness for the Persona
		// webhook example.
		for _, mr := range s.methodRoutes {
			path := "/methods/" + mr.MethodID + "/" + mr.Path
			switch mr.Method {
			case http.MethodPost:
				r.Method(http.MethodPost, path, mr.Handler)
			case http.MethodGet:
				r.Method(http.MethodGet, path, mr.Handler)
			default:
				r.Handle(path, mr.Handler)
			}
		}
	})

	// Top-level alias the README sketch documents. We keep BOTH paths for
	// the credential issue/enrollment endpoints during v0.1 so the README and
	// the historical sketch stay consistent.
	r.Post("/enrollment/start", s.handleStartEnrollment)
	r.Post("/credentials/issue", s.handleIssueCredential)

	return r
}

// ----------------------------------------------------------------------------
// Middleware
// ----------------------------------------------------------------------------

// requestLogger writes one JSON line per request in the shape Cloud Logging
// parses into a structured entry (severity + httpRequest), so the console
// can filter by status and alert on ERROR without a log-based parser.
//
// It logs the chi route pattern, never the raw path: GET
// /v1/sessions/{sessionId} carries a bearer session ID in the path, and the
// magic-link route carries its token in the query string.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		writeRequestLog(os.Stdout, r, sw.status, time.Since(start))
	})
}

type requestLogEntry struct {
	Severity    string         `json:"severity"`
	Message     string         `json:"message"`
	HTTPRequest httpRequestLog `json:"httpRequest"`
	Trace       string         `json:"trace,omitempty"`
}

type httpRequestLog struct {
	RequestMethod string `json:"requestMethod"`
	RequestURL    string `json:"requestUrl"`
	Status        int    `json:"status"`
	Latency       string `json:"latency"`
}

var logMu sync.Mutex

func writeRequestLog(out io.Writer, r *http.Request, status int, elapsed time.Duration) {
	route := routePattern(r)
	severity := "INFO"
	switch {
	case status >= 500:
		severity = "ERROR"
	case status >= 400:
		severity = "WARNING"
	}
	entry := requestLogEntry{
		Severity: severity,
		Message:  fmt.Sprintf("%s %s %d %s", r.Method, route, status, elapsed.Truncate(time.Millisecond)),
		HTTPRequest: httpRequestLog{
			RequestMethod: r.Method,
			RequestURL:    route,
			Status:        status,
			Latency:       fmt.Sprintf("%.3fs", elapsed.Seconds()),
		},
	}
	// Cloud Run sets X-Cloud-Trace-Context: TRACE_ID/SPAN_ID;o=1. Passing the
	// trace ID through groups this line with Cloud Run's own request log.
	if tc := r.Header.Get("X-Cloud-Trace-Context"); tc != "" {
		entry.Trace, _, _ = strings.Cut(tc, "/")
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	_, _ = out.Write(append(b, '\n'))
}

// routePattern returns the matched chi pattern (e.g.
// "/v1/sessions/{sessionId}"), or "unmatched" for a 404 so arbitrary
// client-chosen paths never reach the log.
func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	return "unmatched"
}

// corsMiddleware adds CORS headers permissive enough for the configured
// allowlist of origins to call the API from a browser. A request from an
// origin not on the list gets no Access-Control-* headers — same-origin
// requests still work; the browser refuses cross-origin.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.isOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			w.Header().Set("Access-Control-Max-Age", "300")
			// Retry-After is not CORS-safelisted; without this the web app
			// can't read how long a 429 asks it to wait.
			w.Header().Set("Access-Control-Expose-Headers", "Retry-After")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) isOriginAllowed(origin string) bool {
	for _, allowed := range s.cfg.CORSAllowedOrigins {
		// Treat "*" as the universal wildcard.
		if allowed == "*" {
			return true
		}
		if strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("server: panic in handler: %v", rec)
				writeError(w, http.StatusInternalServerError, "panic", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
