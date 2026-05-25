// Command server starts the Personhood reference REST issuer.
//
// Configuration comes from environment variables (see env.example at the
// repo root). Required: ISSUER_ED25519_SK_B64. Generate one with:
//
//	go run ./src/server/cmd/gen-key
//
// then export the printed seed before running this binary.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sagearbor/personhood/src/server"
)

func main() {
	cfg, err := server.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("server: load config: %v", err)
	}

	magicLinkBaseURL, err := joinURL(cfg.PublicURL, "/v1/methods/email/verify")
	if err != nil {
		log.Fatalf("server: derive magic link base URL: %v", err)
	}

	reg, err := server.DefaultMethods(magicLinkBaseURL)
	if err != nil {
		log.Fatalf("server: build default registry: %v", err)
	}

	srv, err := server.NewServer(cfg, server.Dependencies{Registry: reg})
	if err != nil {
		log.Fatalf("server: construct: %v", err)
	}

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	idle := make(chan struct{})
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		log.Println("server: shutdown signal received")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("server: shutdown error: %v", err)
		}
		close(idle)
	}()

	log.Printf("server: listening on %s (public URL %s, issuer %s)", cfg.Addr, cfg.PublicURL, srv.IssuerDID())
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: listen: %v", err)
	}
	<-idle
	log.Println("server: stopped cleanly")
}

func joinURL(base, p string) (string, error) {
	if base == "" {
		return p, nil
	}
	if len(p) > 0 && p[0] == '/' && len(base) > 0 && base[len(base)-1] == '/' {
		return base + p[1:], nil
	}
	if len(p) > 0 && p[0] != '/' && len(base) > 0 && base[len(base)-1] != '/' {
		return base + "/" + p, nil
	}
	return base + p, nil
}
