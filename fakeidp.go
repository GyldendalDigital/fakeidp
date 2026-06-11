// Package fakeidp implements a mock OpenID Connect provider for use in
// integration tests. It signs real RS256 tokens, serves a discovery
// document and JWKS, and supports the authorization code and refresh
// token grants, token revocation, userinfo, and failure injection.
//
// The package is safe to embed in tests via httptest:
//
//	s, _ := fakeidp.New(fakeidp.Options{Users: fakeidp.DefaultUsers()})
//	ts := httptest.NewServer(s.Handler())
//	s.SetIssuer(ts.URL)
//
// or use NewTestServer which does the above and registers cleanup.
package fakeidp

import (
	crypto_rand "crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Options configures a Server. The zero value is not usable: Users is
// required, everything else has sensible test defaults.
type Options struct {
	Issuer       string                    // optional; can be set after the listener is up via SetIssuer
	ClientID     string                    // default "test-client"
	ClientSecret string                    // optional; not verified at the token endpoint
	Users        map[string]map[string]any // required; sub -> claims. See DefaultUsers.
	KeyRotate    time.Duration             // 0 disables the rotation loop (default for tests)
	KeyKeep      int                       // number of keys kept in the JWKS, default 3
	LatencyP95   time.Duration             // 0 disables latency injection
	ErrorRate    float64                   // 0..1 probability of a mock 500, default 0
	R429Rate     float64                   // 0..1 probability of a mock 429, default 0
	Seed         uint64                    // RNG seed for random user picks and failure injection; 0 means 1
	Logger       *slog.Logger              // default: discard
	DebugTokens  bool                      // log issued tokens at debug level
}

// Server is a mock OpenID Connect provider.
type Server struct {
	clientID     string
	clientSecret string
	keyRotate    time.Duration
	keyKeep      int
	latencyP95   time.Duration
	errPct       float64
	r429Pct      float64
	debugTokens  bool
	logger       *slog.Logger

	issuerMu sync.RWMutex
	issuer   string

	keysMu sync.RWMutex
	keys   []KeyPair // [0] is current, others are previous

	authzMu sync.Mutex
	authz   map[string]authCode

	refreshMu   sync.Mutex
	refresh     map[string]refreshGrant
	revokeCalls int

	usersMu      sync.RWMutex
	users        map[string]map[string]any // sub -> claims
	userSubs     []string
	defaultLogin string

	rndMu sync.Mutex
	rnd   *rand.Rand

	mux *http.ServeMux

	closeOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
}

type authCode struct {
	Sub       string
	ClientID  string
	Redirect  string
	ExpiresAt time.Time
	CodeChal  string
	IssuedAt  time.Time
	Nonce     string
	Scope     string
}

type refreshGrant struct {
	Sub       string
	ExpiresAt time.Time
	Scope     string
}

// New constructs a Server from opts. It does no network I/O and starts
// no goroutines unless KeyRotate > 0.
func New(opts Options) (*Server, error) {
	if len(opts.Users) == 0 {
		return nil, fmt.Errorf("fakeidp: Options.Users is required; use fakeidp.DefaultUsers() for a canned set")
	}
	if opts.ErrorRate < 0 || opts.ErrorRate > 1 {
		return nil, fmt.Errorf("fakeidp: ErrorRate must be in [0,1], got %v", opts.ErrorRate)
	}
	if opts.R429Rate < 0 || opts.R429Rate > 1 {
		return nil, fmt.Errorf("fakeidp: R429Rate must be in [0,1], got %v", opts.R429Rate)
	}
	if opts.ErrorRate+opts.R429Rate > 1 {
		return nil, fmt.Errorf("fakeidp: ErrorRate+R429Rate must not exceed 1")
	}

	clientID := opts.ClientID
	if clientID == "" {
		clientID = "test-client"
	}
	keyKeep := opts.KeyKeep
	if keyKeep <= 0 {
		keyKeep = 3
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	seed := opts.Seed
	if seed == 0 {
		seed = 1
	}

	users := make(map[string]map[string]any, len(opts.Users))
	for sub, claims := range opts.Users {
		if len(claims) == 0 {
			return nil, fmt.Errorf("fakeidp: user %q has empty claims", sub)
		}
		c := make(map[string]any, len(claims))
		for k, v := range claims {
			c[k] = v
		}
		c["sub"] = sub
		users[sub] = c
	}

	s := &Server{
		issuer:       opts.Issuer,
		clientID:     clientID,
		clientSecret: opts.ClientSecret,
		keyRotate:    opts.KeyRotate,
		keyKeep:      keyKeep,
		latencyP95:   opts.LatencyP95,
		errPct:       opts.ErrorRate,
		r429Pct:      opts.R429Rate,
		debugTokens:  opts.DebugTokens,
		logger:       logger,
		keys:         []KeyPair{newKeyPair()},
		authz:        map[string]authCode{},
		refresh:      map[string]refreshGrant{},
		users:        users,
		rnd:          rand.New(rand.NewPCG(seed, 42)),
		mux:          http.NewServeMux(),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	s.rebuildUserIndex()

	s.mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	s.mux.HandleFunc("/authorize", s.authorize)
	s.mux.HandleFunc("/token", s.token)
	s.mux.HandleFunc("/revoke", s.revoke)
	s.mux.HandleFunc("/jwks", s.jwksHandler)
	s.mux.HandleFunc("/userinfo", s.userinfo)
	s.mux.HandleFunc("/healthz", s.health)

	if s.keyRotate > 0 {
		go s.rotateKeysLoop()
	} else {
		close(s.done)
	}
	return s, nil
}

// Handler returns the HTTP handler serving all provider endpoints.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// SetIssuer updates the issuer emitted in the discovery document and the
// iss claim of issued tokens. Call it once the listener URL is known.
func (s *Server) SetIssuer(url string) {
	s.issuerMu.Lock()
	s.issuer = strings.TrimRight(url, "/")
	s.issuerMu.Unlock()
}

// Issuer returns the current issuer.
func (s *Server) Issuer() string {
	s.issuerMu.RLock()
	defer s.issuerMu.RUnlock()
	return s.issuer
}

// Close stops the key rotation goroutine, if any. It is idempotent and
// safe to call from t.Cleanup.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.stop)
	})
	<-s.done
	return nil
}

// AddUser adds or replaces a user mid-flow. The sub claim is forced to
// match the key.
func (s *Server) AddUser(sub string, claims map[string]any) {
	c := make(map[string]any, len(claims)+1)
	for k, v := range claims {
		c[k] = v
	}
	c["sub"] = sub
	s.usersMu.Lock()
	s.users[sub] = c
	s.rebuildUserIndexLocked()
	s.usersMu.Unlock()
}

// SetDefaultLogin pins which user /authorize selects when the request has
// no login parameter. Useful when the relying party under test cannot be
// told to forward a login hint. An empty sub restores the random pick.
func (s *Server) SetDefaultLogin(sub string) {
	s.usersMu.Lock()
	s.defaultLogin = sub
	s.usersMu.Unlock()
}

// User returns a copy of the claims for sub, or nil if unknown.
func (s *Server) User(sub string) map[string]any {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	u, ok := s.users[sub]
	if !ok {
		return nil
	}
	c := make(map[string]any, len(u))
	for k, v := range u {
		c[k] = v
	}
	return c
}

// RevokeCalls reports how many times the /revoke endpoint has been hit.
// Useful for asserting that a relying party revoked tokens on logout.
func (s *Server) RevokeCalls() int {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	return s.revokeCalls
}

// DefaultUsers returns a small set of hard-coded personas for tests that
// do not care about specific users.
func DefaultUsers() map[string]map[string]any {
	return map[string]map[string]any{
		"user-alice": {
			"email":              "alice@example.test",
			"email_verified":     true,
			"name":               "Alice Andersen",
			"preferred_username": "alice",
		},
		"user-bob": {
			"email":              "bob@example.test",
			"email_verified":     true,
			"name":               "Bob Berntsen",
			"preferred_username": "bob",
		},
		"user-carol": {
			"email":              "carol@example.test",
			"email_verified":     false,
			"name":               "Carol Carlsen",
			"preferred_username": "carol",
		},
		"user-dag": {
			"email":              "dag@example.test",
			"email_verified":     true,
			"name":               "Dag Dagsen",
			"preferred_username": "dag",
		},
	}
}

func (s *Server) rebuildUserIndex() {
	s.usersMu.Lock()
	s.rebuildUserIndexLocked()
	s.usersMu.Unlock()
}

func (s *Server) rebuildUserIndexLocked() {
	s.userSubs = s.userSubs[:0]
	for sub := range s.users {
		s.userSubs = append(s.userSubs, sub)
	}
	sort.Strings(s.userSubs)
}

func (s *Server) pickRandomSub() string {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	if s.defaultLogin != "" {
		return s.defaultLogin
	}
	if len(s.userSubs) == 0 {
		return ""
	}
	s.rndMu.Lock()
	i := s.rnd.IntN(len(s.userSubs))
	s.rndMu.Unlock()
	return s.userSubs[i]
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := crypto_rand.Read(b); err != nil {
		panic(err)
	}
	return b64url(b)
}
