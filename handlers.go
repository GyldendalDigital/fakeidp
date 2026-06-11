package fakeidp

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) maybeDelayAndFail(w http.ResponseWriter) bool {
	// Latency: very rough log-normal around p95
	if s.latencyP95 > 0 {
		// Pick log-normal so long tail exists; median ~ p95/4.3 (approx)
		mu := math.Log(float64(s.latencyP95.Milliseconds())/4.3 + 1)
		sigma := 0.8
		s.rndMu.Lock()
		norm := s.rnd.NormFloat64()
		s.rndMu.Unlock()
		ms := int(math.Exp(norm*sigma + mu))
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
	// Error rate
	s.rndMu.Lock()
	p := s.rnd.Float64()
	s.rndMu.Unlock()
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
	base := s.Issuer()
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
	user := s.User(sub)
	if user == nil {
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

	cb, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	cbq := cb.Query()
	cbq.Set("code", code)
	if state != "" {
		cbq.Set("state", state)
	}
	cb.RawQuery = cbq.Encode()

	s.logger.Info("Authorize granted", "sub", sub, "client_id", clientID, "code", code, "name", user["name"])
	http.Redirect(w, r, cb.String(), http.StatusFound)
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
	s.refreshMu.Lock()
	s.revokeCalls++
	if gr, ok := s.refresh[token]; ok {
		s.logger.Info("Revoked refresh token for sub", "sub", gr.Sub)
		delete(s.refresh, token)
	} else {
		// per RFC7009, revoking a non-existent token is still 200 OK
		s.logger.Warn("Revoke called for unknown token", "token", token)
	}
	s.refreshMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if s.maybeDelayAndFail(w) {
		return
	}
	writeJSON(w, s.JWKS())
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	if s.maybeDelayAndFail(w) {
		return
	}
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	raw := strings.TrimSpace(authz[len("bearer "):])

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected alg %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		k, ok := s.keyByKID(kid)
		if !ok {
			return nil, fmt.Errorf("unknown kid %q", kid)
		}
		return k.Public, nil
	})
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	sub, _ := claims["sub"].(string)
	user := s.User(sub)
	if user == nil {
		http.Error(w, "no such user", http.StatusUnauthorized)
		return
	}
	writeJSON(w, user)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) issueTokens(sub, scope, nonce string) (idToken, accessToken string, err error) {
	now := time.Now()
	key := s.currentKey()
	issuer := s.Issuer()

	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": sub,
		"aud": s.clientID,
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	s.mergeUserClaims(claims, sub)

	idt := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idt.Header["kid"] = key.KID
	idSigned, err := idt.SignedString(key.Private)
	if err != nil {
		return "", "", err
	}

	acl := jwt.MapClaims{
		"iss":   issuer,
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
		s.logger.Debug("Issued tokens", "sub", sub, "id_token", idSigned, "access_token", atSigned)
	}
	return idSigned, atSigned, nil
}

// IssueIDToken mints a signed id_token for sub without driving the full
// authorization flow. Useful for tests asserting verification logic in
// isolation.
func (s *Server) IssueIDToken(sub, scope, nonce string) (string, error) {
	idt, _, err := s.issueTokens(sub, scope, nonce)
	return idt, err
}

// IssueAccessToken mints a signed access token for sub without driving
// the full authorization flow.
func (s *Server) IssueAccessToken(sub, scope string) (string, error) {
	_, at, err := s.issueTokens(sub, scope, "")
	return at, err
}

func (s *Server) issueRefresh(sub, scope string) string {
	rt := "r." + randomURLSafe(32)
	s.refreshMu.Lock()
	s.refresh[rt] = refreshGrant{Sub: sub, ExpiresAt: time.Now().Add(24 * time.Hour), Scope: scope}
	s.refreshMu.Unlock()
	return rt
}

func (s *Server) mergeUserClaims(dst jwt.MapClaims, sub string) {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	if u, ok := s.users[sub]; ok {
		for k, v := range u {
			if k == "sub" {
				continue // sub is set explicitly
			}
			dst[k] = v
		}
	}
}
