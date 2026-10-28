// Command opaque-sidecar is the Vercel function that serves the OPAQUE
// server-side protocol. It exists so OPAQUE works on serverless hosting, where
// there is no loopback to bind a sidecar to and no second service to run.
//
// It reuses pkg/sidecar from the CLI module rather than reimplementing the
// protocol: the RFC 9807 messages match across implementations, but the
// envelope layouts do not, and mixing them breaks enrolled accounts.
//
// Fail-closed posture: without OPAQUE_SIDECAR_TOKEN or valid
// OPAQUE_SERVER_KEY_MATERIAL in the environment, every request answers 503.
// It never generates key material. A record registered under one key set
// cannot authenticate under another, so a deployment that silently invented
// keys would strand accounts.
package handler

import (
	"net/http"
	"strings"
	"sync"

	"github.com/The-17/agentsecrets/pkg/sidecar"
)

var (
	once    sync.Once
	handler http.Handler
	initErr error
)

// build is separated from the cached path so tests can drive it directly.
func build() (http.Handler, error) {
	// The boolean is dev-generate-keys. A function that invented key material
	// on cold start would strand every record registered against a previous
	// instance, so production must always pass false.
	s, err := sidecar.New(false)
	if err != nil {
		return nil, err
	}
	return s.Mux(), nil
}

func initSidecar() {
	handler, initErr = build()
}

// Handler is the Vercel entry point.
//
// Vercel delivers the original request URI, so on the deployment the mux sees
// /opaque-sidecar/... while it registers bare /v1/... and /healthz. Requests
// carrying the mount prefix are stripped; anything else passes through so the
// loopback binary and the function keep serving one route table.
func Handler(w http.ResponseWriter, r *http.Request) {
	once.Do(initSidecar)
	if initErr != nil {
		http.Error(w, "opaque sidecar unavailable", http.StatusServiceUnavailable)
		return
	}
	const mount = "/opaque-sidecar"
	if strings.HasPrefix(r.URL.Path, mount) {
		http.StripPrefix(mount, handler).ServeHTTP(w, r)
		return
	}
	handler.ServeHTTP(w, r)
}

