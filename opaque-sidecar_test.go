package handler

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/bytemare/opaque"

	"github.com/The-17/agentsecrets/pkg/sidecar"
)

// reset un-caches the package-level handler so each test builds its own.
func reset() {
	once = sync.Once{}
	handler = nil
	initErr = nil
}

// material returns valid key material, because the sidecar refuses to start
// with arbitrary bytes: the OPRF key is a ristretto255 scalar.
func material(t *testing.T) string {
	t.Helper()
	conf := opaque.DefaultConfiguration()
	skm, err := sidecar.GenerateKeyMaterial(conf)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := sidecar.FormatKeyMaterial(skm)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFailsClosedWithoutConfiguration(t *testing.T) {
	t.Setenv("OPAQUE_SIDECAR_TOKEN", "test-token")
	t.Setenv("OPAQUE_SERVER_KEY_MATERIAL", "")
	reset()

	if _, err := build(); err == nil {
		t.Fatal("build succeeded without key material; this deployment would strand accounts")
	}

	rr := httptest.NewRecorder()
	Handler(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when unconfigured, got %d", rr.Code)
	}
}

func TestServesHealthzAndGatesTheProtocol(t *testing.T) {
	t.Setenv("OPAQUE_SIDECAR_TOKEN", "test-token")
	t.Setenv("OPAQUE_SERVER_KEY_MATERIAL", material(t))
	reset()

	h, err := build()
	if err != nil {
		t.Fatalf("build with valid material: %v", err)
	}

	health := httptest.NewRecorder()
	h.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("healthz: expected 200, got %d", health.Code)
	}

	ungated := httptest.NewRecorder()
	h.ServeHTTP(ungated, httptest.NewRequest(http.MethodPost, "/v1/register/response", nil))
	if ungated.Code != http.StatusUnauthorized {
		t.Fatalf("protocol route without a bearer token: expected 401, got %d", ungated.Code)
	}
}

func TestHandlerEntryServesTheSameRoutes(t *testing.T) {
	t.Setenv("OPAQUE_SIDECAR_TOKEN", "test-token")
	t.Setenv("OPAQUE_SERVER_KEY_MATERIAL", material(t))
	reset()

	rr := httptest.NewRecorder()
	Handler(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("Handler entrypoint: expected 200 for healthz, got %d", rr.Code)
	}
}
