package server

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Router builds the http.Handler that drives the server. The returned router
// is fresh on every call; tests typically call this once and pass it to
// httptest.NewServer.
//
// Route map (kept in sync with README.md):
//
//	GET  /healthz                              — liveness probe
//	GET  /.well-known/did.json                 — issuer DID document
//	GET  /v1/methods                           — list registered methods
//	POST /enrollment/start                     — create a session
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

	r.Get("/healthz", s.handleHealth)
	r.Get("/.well-known/did.json", s.handleDIDDocument)

	r.Route("/v1", func(r chi.Router) {
		r.Get("/methods", s.handleListMethods)

		r.Route("/methods/{methodId}", func(r chi.Router) {
			r.Post("/begin", s.handleBeginMethod)
			r.Post("/complete", s.handleCompleteMethod)
		})

		// Explicit landing route for the email magic link. Kept under /v1
		// so a single base URL covers every public route the server emits.
		r.Get("/methods/email/verify", s.handleEmailMagicLink)

		r.Post("/credentials/issue", s.handleIssueCredential)
		r.Get("/status-list/{listId}", s.handleStatusList)
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

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.status, time.Since(start).Truncate(time.Millisecond))
	})
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
