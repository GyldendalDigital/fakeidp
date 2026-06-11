package fakeidp

import (
	"net/http/httptest"
	"testing"
)

// NewTestServer constructs a Server, starts an httptest.Server in front of
// it, and points the issuer at the resulting URL. Cleanup of both is
// registered via tb.Cleanup. Any Issuer set in opts is overwritten by the
// httptest URL.
func NewTestServer(tb testing.TB, opts Options) (*Server, *httptest.Server) {
	tb.Helper()
	s, err := New(opts)
	if err != nil {
		tb.Fatalf("fakeidp.New: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	s.SetIssuer(ts.URL)
	tb.Cleanup(func() {
		ts.Close()
		_ = s.Close()
	})
	return s, ts
}
