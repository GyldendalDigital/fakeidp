package main

import (
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // for thumbprint-ish kid
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type KeyPair struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
	KID     string
	Added   time.Time
}

type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type Server struct {
	issuer       string
	port         int
	clientID     string
	clientSecret string
	alg          string // RS256 only in this demo
	keyRotate    time.Duration
	keyKeep      int

	latencyP95  time.Duration
	errPct      float64 // 0..1
	r429Pct     float64 // 0..1
	debugTokens bool

	keysMu sync.RWMutex
	keys   []KeyPair // [0] is current, others are previous

	authzMu sync.Mutex
	authz   map[string]authCode

	refreshMu sync.Mutex
	refresh   map[string]refreshGrant

	users    map[string]map[string]any // username -> claims
	userSubs []string

	http *http.ServeMux
	rnd  *rand.Rand
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

type userStateFile struct {
	Users map[string]map[string]any `json:"users"`
}

type startupConfig struct {
	UserStatePath string
	UserCount     int
}

var defaultUserLanguages = []string{
	"finnish",
	"swedish",
	"norwegian",
	"sindarin",
	"italian",
	"french",
	"german",
	"japanese_romaji",
	"spanish",
	"portuguese",
	"icelandic",
	"kobaian",
}

func mustEnv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func parseDurationEnv(key, def string) time.Duration {
	v := mustEnv(key, def)
	d, err := time.ParseDuration(v)
	if err != nil {
		panic(err)
	}
	return d
}

func parseFloatEnv(key, def string) float64 {
	v := mustEnv(key, def)
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		panic(err)
	}
	return f
}

func b64url(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), "=")
}

func newKeyPair() KeyPair {
	priv, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pub := &priv.PublicKey

	// Make a stable short kid from the public modulus (NOT spec thumbprint; good enough for tests)
	nBytes := pub.N.Bytes()
	sum := sha1.Sum(nBytes)
	kid := b64url(sum[:8])
	return KeyPair{Private: priv, Public: pub, KID: kid, Added: time.Now()}
}

func (s *Server) currentKey() KeyPair {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	return s.keys[0]
}

func (s *Server) jwks() JWKS {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	js := JWKS{Keys: make([]JWK, 0, len(s.keys))}
	for _, k := range s.keys {
		js.Keys = append(js.Keys, JWK{
			Kty: "RSA",
			N:   b64url(k.Public.N.Bytes()),
			E:   b64url(bigEndianUint(k.Public.E)),
			Alg: "RS256",
			Use: "sig",
			Kid: k.KID,
		})
	}
	return js
}

func bigEndianUint(v int) []byte {
	// for exponent 65537 -> 0x01 0x00 0x01
	if v == 0 {
		return []byte{0}
	}
	var bytes []byte
	for v > 0 {
		bytes = append([]byte{byte(v & 0xff)}, bytes...)
		v >>= 8
	}
	return bytes
}

func (s *Server) rotateKeysLoop() {
	t := time.NewTicker(s.keyRotate)
	defer t.Stop()
	for range t.C {
		k := newKeyPair()
		s.keysMu.Lock()
		s.keys = append([]KeyPair{k}, s.keys...)
		if len(s.keys) > s.keyKeep {
			s.keys = s.keys[:s.keyKeep]
		}
		s.keysMu.Unlock()
		slog.Info("Rotated keys", "new_kid", k.KID, "total_keys", len(s.keys))
	}
}

func (s *Server) maybeDelayAndFail(w http.ResponseWriter) bool {
	// Latency: very rough log-normal around p95
	if s.latencyP95 > 0 {
		// Pick log-normal so long tail exists; median ~ p95/4.3 (approx)
		mu := math.Log(float64(s.latencyP95.Milliseconds())/4.3 + 1)
		sigma := 0.8
		ms := int(math.Exp(s.rnd.NormFloat64()*sigma + mu))
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
	// Error rate
	p := s.rnd.Float64()
	switch {
	case p < s.errPct:
		http.Error(w, "mock 500 from IdP", http.StatusInternalServerError)
		return true
	case p < s.errPct+s.r429Pct:
		http.Error(w, "mock 429 from IdP", http.StatusTooManyRequests)
		return true
	default:
		return false
	}
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	if s.maybeDelayAndFail(w) {
		return
	}
	base := s.issuer
	resp := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"revocation_endpoint":                   base + "/revoke",
		"jwks_uri":                              base + "/jwks",
		"userinfo_endpoint":                     base + "/userinfo",
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "none"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "name", "preferred_username"},
	}
	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	if s.maybeDelayAndFail(w) {
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")
	scope := q.Get("scope")

	if clientID == "" || clientID != s.clientID {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	sub := q.Get("login")
	if sub == "" {
		sub = s.pickRandomSub()
	}
	if _, ok := s.users[sub]; !ok {
		http.Error(w, "no such user", http.StatusUnauthorized)
		return
	}

	code := randomURLSafe(24)
	s.authzMu.Lock()
	s.authz[code] = authCode{
		Sub:       sub,
		ClientID:  clientID,
		Redirect:  redirectURI,
		ExpiresAt: time.Now().Add(2 * time.Minute),
		IssuedAt:  time.Now(),
		Nonce:     nonce,
		Scope:     scope,
	}
	s.authzMu.Unlock()

	cb, _ := url.Parse(redirectURI)
	cbq := cb.Query()
	cbq.Set("code", code)
	if state != "" {
		cbq.Set("state", state)
	}
	cb.RawQuery = cbq.Encode()

	slog.Info("Authorize granted", "sub", sub, "client_id", clientID, "code", code, "name", s.users[sub]["name"])
	http.Redirect(w, r, cb.String(), http.StatusFound)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if s.maybeDelayAndFail(w) {
		return
	}
	token := r.Form.Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	if _, ok := s.refresh[token]; !ok {
		// per RFC7009, revoking a non-existent token is still 200 OK
		slog.Warn("Revoke called for unknown token", "token", token)
	} else {
		s.refreshMu.Lock()
		slog.Info("Revoked refresh token for sub", "sub", s.refresh[token].Sub)
		delete(s.refresh, token)
		s.refreshMu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if s.maybeDelayAndFail(w) {
		return
	}

	grantType := r.Form.Get("grant_type")
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		clientID = r.Form.Get("authorization") // allow tests to be sloppy
	}
	if clientID != "" && clientID != s.clientID {
		http.Error(w, "invalid client", http.StatusUnauthorized)
		return
	}

	switch grantType {
	case "authorization_code":
		code := r.Form.Get("code")
		redirectURI := r.Form.Get("redirect_uri")
		s.authzMu.Lock()
		ac, ok := s.authz[code]
		if ok {
			delete(s.authz, code) // one-time use
		}
		s.authzMu.Unlock()
		if !ok || time.Now().After(ac.ExpiresAt) {
			http.Error(w, "invalid_code", http.StatusBadRequest)
			return
		}
		if redirectURI != ac.Redirect {
			http.Error(w, "redirect_mismatch", http.StatusBadRequest)
			return
		}
		rt := s.issueRefresh(ac.Sub, ac.Scope)
		idt, at, err := s.issueTokens(ac.Sub, ac.Scope, ac.Nonce)
		if err != nil {
			http.Error(w, "signing_error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"token_type":    "Bearer",
			"expires_in":    3600,
			"access_token":  at,
			"id_token":      idt,
			"refresh_token": rt,
			"scope":         ac.Scope,
		})
	case "refresh_token":
		rt := r.Form.Get("refresh_token")
		s.refreshMu.Lock()
		gr, ok := s.refresh[rt]
		if ok && time.Now().After(gr.ExpiresAt) {
			ok = false
			delete(s.refresh, rt)
		}
		s.refreshMu.Unlock()
		if !ok {
			http.Error(w, "invalid_refresh", http.StatusBadRequest)
			return
		}
		idt, at, err := s.issueTokens(gr.Sub, gr.Scope, "")
		if err != nil {
			http.Error(w, "signing_error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"token_type":   "Bearer",
			"expires_in":   3600,
			"access_token": at,
			"id_token":     idt,
			"scope":        gr.Scope,
		})
	default:
		http.Error(w, "unsupported_grant", http.StatusBadRequest)
	}
}

func (s *Server) issueTokens(sub, scope, nonce string) (idToken, accessToken string, err error) {
	now := time.Now()
	key := s.currentKey()

	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": sub,
		"aud": s.clientID,
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
		"nonce": func() any {
			if nonce == "" {
				return nil
			}
			return nonce
		}(),
	}
	s.mergeUserClaims(claims, sub)

	idt := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idt.Header["kid"] = key.KID
	idSigned, err := idt.SignedString(key.Private)
	if err != nil {
		return "", "", err
	}

	acl := jwt.MapClaims{
		"iss":   s.issuer,
		"sub":   sub,
		"aud":   s.clientID,
		"iat":   now.Unix(),
		"exp":   now.Add(1 * time.Hour).Unix(),
		"scope": scope,
	}
	at := jwt.NewWithClaims(jwt.SigningMethodRS256, acl)
	at.Header["kid"] = key.KID
	atSigned, err := at.SignedString(key.Private)
	if err != nil {
		return "", "", err
	}
	if s.debugTokens {
		slog.Debug("Issued tokens", "sub", sub, "id_token", idSigned, "access_token", atSigned)
	}
	return idSigned, atSigned, nil
}

func (s *Server) issueRefresh(sub, scope string) string {
	rt := "r." + randomURLSafe(32)
	s.refreshMu.Lock()
	s.refresh[rt] = refreshGrant{Sub: sub, ExpiresAt: time.Now().Add(24 * time.Hour), Scope: scope}
	s.refreshMu.Unlock()
	return rt
}

func (s *Server) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if s.maybeDelayAndFail(w) {
		return
	}
	writeJSON(w, s.jwks())
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	if s.maybeDelayAndFail(w) {
		return
	}
	// Extremely basic: extract sub from a Bearer token if present, else use fixed
	_ = r.ParseForm()
	authz := r.Header.Get("Authorization")
	sub := "user-123"
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		// Don't verify; it's a mock. Just parse body for demo.
		token := strings.TrimSpace(authz[7:])
		parts := strings.Split(token, ".")
		if len(parts) == 3 {
			// lazy decode claims for "sub" (no validation)
			if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
				var m map[string]any
				if json.Unmarshal(b, &m) == nil {
					if v, ok := m["sub"].(string); ok && v != "" {
						sub = v
					}
				}
			}
		}
	}
	claims := s.users[sub]
	if claims == nil {
		http.Error(w, "no such user", http.StatusUnauthorized)
		return
	}
	writeJSON(w, claims)
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := crypto_rand.Read(b); err != nil {
		panic(err)
	}
	return b64url(b)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func pemForKey(k *rsa.PrivateKey) string {
	b := x509.MarshalPKCS1PrivateKey(k)
	p := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
	return string(pem.EncodeToMemory(p))
}

func (s *Server) initUserIndex() {
	s.userSubs = s.userSubs[:0]
	for sub := range s.users {
		s.userSubs = append(s.userSubs, sub)
	}
	sort.Strings(s.userSubs)
	slog.Info("Initialized user index", "count", len(s.userSubs))
}

func (s *Server) pickRandomSub() string {
	if len(s.userSubs) == 0 {
		return "user-123" // or panic/log
	}
	return s.userSubs[s.rnd.IntN(len(s.userSubs))]
}

func (s *Server) mergeUserClaims(dst jwt.MapClaims, sub string) {
	if u, ok := s.users[sub]; ok {
		for k, v := range u {
			if k == "sub" {
				continue
			} // we'll set sub explicitly
			dst[k] = v
		}
	}
}

func (s *Server) generateAdditionalUsers(lang string, n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}

	type persona struct {
		Name        string `json:"name"`
		City        string `json:"city"`
		DateOfBirth string `json:"date_of_birth"`
		Email       string `json:"email"`
	}
	type apiResp struct {
		Response []persona `json:"response"`
		Results  int       `json:"results"`
	}

	// Build URL with num=n
	url := fmt.Sprintf("https://svante.tynn.is/personas/%s/generate?num=%d", lang, n)

	// Reasonable timeout
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("create request for %s users: %w", lang, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch %s users: %w", lang, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("fetch %s users: status=%d body=%q", lang, resp.StatusCode, string(body))
	}

	var parsed apiResp
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return 0, fmt.Errorf("decode %s users: %w", lang, err)
	}

	if s.users == nil {
		s.users = make(map[string]map[string]any)
	}

	added := 0
	for _, p := range parsed.Response {
		if p.Email == "" || p.Name == "" {
			continue
		}
		// preferred_username = part before '@'
		at := strings.IndexByte(p.Email, '@')
		preferred := p.Email
		if at > 0 {
			preferred = p.Email[:at]
		}

		// unique sub
		sub := "user-" + lang + "-" + randomURLSafe(8)

		s.users[sub] = map[string]any{
			"sub":                sub,
			"email":              p.Email,
			"email_verified":     true,
			"name":               p.Name,
			"preferred_username": preferred,
			// extra handy fields for your proxy normalization/tests:
			"city":          p.City,
			"date_of_birth": p.DateOfBirth,
		}
		added++
	}

	slog.Info("Generated additional users", "language", lang, "added", added)
	return added, nil
}

func distributeCount(total, buckets int) []int {
	counts := make([]int, buckets)
	if total <= 0 || buckets <= 0 {
		return counts
	}

	base := total / buckets
	remainder := total % buckets
	for i := range counts {
		counts[i] = base
		if i < remainder {
			counts[i]++
		}
	}
	return counts
}

func (s *Server) generateUsers(total int) error {
	if total < 0 {
		return fmt.Errorf("user count must be >= 0")
	}
	counts := distributeCount(total, len(defaultUserLanguages))
	generated := 0
	for i, lang := range defaultUserLanguages {
		added, err := s.generateAdditionalUsers(lang, counts[i])
		if err != nil {
			return err
		}
		generated += added
	}
	if generated != total {
		return fmt.Errorf("generated %d users, expected %d", generated, total)
	}
	return nil
}

func loadUserState(path string) (map[string]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var state userStateFile
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode user state: %w", err)
	}
	if state.Users == nil {
		return nil, fmt.Errorf("decode user state: missing users")
	}
	for sub, claims := range state.Users {
		if claims == nil {
			return nil, fmt.Errorf("decode user state: user %q has empty claims", sub)
		}
		if claimSub, ok := claims["sub"].(string); !ok || claimSub == "" {
			claims["sub"] = sub
		}
	}
	return state.Users, nil
}

func saveUserState(path string, users map[string]map[string]any) error {
	state := userStateFile{Users: users}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode user state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create user state directory: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write user state: %w", err)
	}
	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func parseStartupConfig() startupConfig {
	cfg := startupConfig{}
	flag.StringVar(&cfg.UserStatePath, "userstate", "", "path to a JSON file for loading/saving generated users")
	flag.IntVar(&cfg.UserCount, "users", len(defaultUserLanguages)*50, "total number of users to generate when no userstate file is loaded")
	flag.Parse()
	return cfg
}

func loadOrGenerateUsers(s *Server, cfg startupConfig) error {
	if cfg.UserStatePath != "" {
		exists, err := fileExists(cfg.UserStatePath)
		if err != nil {
			return fmt.Errorf("stat userstate file: %w", err)
		}
		if exists {
			users, err := loadUserState(cfg.UserStatePath)
			if err != nil {
				return err
			}
			s.users = users
			slog.Info("Loaded users from userstate file", "path", cfg.UserStatePath, "count", len(s.users))
			return nil
		}
	}

	if err := s.generateUsers(cfg.UserCount); err != nil {
		return err
	}
	slog.Info("Generated users", "count", len(s.users))

	if cfg.UserStatePath != "" {
		if err := saveUserState(cfg.UserStatePath, s.users); err != nil {
			return err
		}
		slog.Info("Saved generated users to userstate file", "path", cfg.UserStatePath, "count", len(s.users))
	}
	return nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	startupCfg := parseStartupConfig()
	rnd := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 42))
	s := &Server{
		issuer:       mustEnv("OIDC_ISSUER", "http://localhost:8080"),
		port:         func() int { p, _ := strconv.Atoi(mustEnv("PORT", "8080")); return p }(),
		clientID:     mustEnv("OIDC_CLIENT_ID", "demo-client"),
		clientSecret: mustEnv("OIDC_CLIENT_SECRET", ""),
		alg:          "RS256",
		keyRotate:    parseDurationEnv("KEY_ROTATE_EVERY", "15m"),
		keyKeep:      func() int { v, _ := strconv.Atoi(mustEnv("KEY_KEEP", "3")); return v }(),
		latencyP95:   parseDurationEnv("LATENCY_P95", "0s"),
		errPct:       parseFloatEnv("ERROR_RATE", "0"),
		r429Pct:      parseFloatEnv("R429_RATE", "0"),
		debugTokens:  mustEnv("DEBUG_TOKENS", "false") == "true",
		authz:        map[string]authCode{},
		refresh:      map[string]refreshGrant{},
		http:         http.NewServeMux(),
		rnd:          rnd,
		users:        make(map[string]map[string]any),
	}
	if err := loadOrGenerateUsers(s, startupCfg); err != nil {
		slog.Error("Failed to initialize users", "error", err)
		os.Exit(1)
	}
	s.initUserIndex()
	// initial keys
	s.keys = []KeyPair{newKeyPair()}

	s.http.HandleFunc("/.well-known/openid-configuration", s.discovery)
	s.http.HandleFunc("/authorize", s.authorize)
	s.http.HandleFunc("/token", s.token)
	s.http.HandleFunc("/revoke", s.revoke)
	s.http.HandleFunc("/jwks", s.jwksHandler)
	s.http.HandleFunc("/userinfo", s.userinfo)
	s.http.HandleFunc("/healthz", s.health)

	go s.rotateKeysLoop()

	addr := fmt.Sprintf(":%d", s.port)
	slog.Info("Mock IdP listening", "address", addr, "issuer", s.issuer)
	slog.Info("Configuration",
		"client_id", s.clientID,
		"key_rotate", s.keyRotate.String(),
		"latency_p95", s.latencyP95.String(),
		"error_rate", s.errPct,
		"r429_rate", s.r429Pct,
		"debug_tokens", s.debugTokens,
		"userstate", startupCfg.UserStatePath,
		"user_count", len(s.users),
	)

	if pk := os.Getenv("PRINT_PRIVATE_KEY"); pk == "1" {
		k := s.currentKey()
		slog.Info("Current private key", "kid", k.KID, "pem", pemForKey(k.Private))
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.http,
		ReadHeaderTimeout: 5 * time.Second,
	}
	err := srv.ListenAndServe()
	if err != nil {
		slog.Error("Server exited", "error", err)
	}
}
