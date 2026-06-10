package fakeidp

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testOpts() Options {
	return Options{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Users:        DefaultUsers(),
	}
}

// noRedirect returns a client that does not follow the authorize redirect,
// so tests can inspect the callback Location header.
func noRedirect() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func getJSON(t *testing.T, url string, dst any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: status %d body %s", url, resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

// driveAuthCode performs /authorize for sub and returns the one-time code.
func driveAuthCode(t *testing.T, ts *httptest.Server, sub, nonce string) (code string) {
	t.Helper()
	authURL := fmt.Sprintf(
		"%s/authorize?client_id=test-client&redirect_uri=%s&state=xyz&nonce=%s&scope=openid+profile+email+offline_access&login=%s",
		ts.URL, url.QueryEscape("https://rp.example.test/callback"), nonce, sub,
	)
	resp, err := noRedirect().Get(authURL)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status=%d body=%s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Query().Get("state"); got != "xyz" {
		t.Fatalf("state=%q want %q", got, "xyz")
	}
	code = loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in callback")
	}
	return code
}

type tokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func exchangeCode(t *testing.T, ts *httptest.Server, code string) tokenResponse {
	t.Helper()
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://rp.example.test/callback"},
		"client_id":    {"test-client"},
	}
	return postToken(t, ts, form, http.StatusOK)
}

func postToken(t *testing.T, ts *httptest.Server, form url.Values, wantStatus int) tokenResponse {
	t.Helper()
	resp, err := http.PostForm(ts.URL+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("token status=%d want %d body=%s", resp.StatusCode, wantStatus, body)
	}
	var tr tokenResponse
	if wantStatus == http.StatusOK {
		if err := json.Unmarshal(body, &tr); err != nil {
			t.Fatalf("decode token response: %v", err)
		}
	}
	return tr
}

// verifyAgainstJWKS parses raw and verifies its signature against the
// published /jwks document, returning the claims.
func verifyAgainstJWKS(t *testing.T, ts *httptest.Server, raw string) jwt.MapClaims {
	t.Helper()
	var jwks JWKS
	getJSON(t, ts.URL+"/jwks", &jwks)

	keyfunc := func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		for _, k := range jwks.Keys {
			if k.Kid != kid {
				continue
			}
			nb, err := jwt.NewParser().DecodeSegment(k.N)
			if err != nil {
				return nil, err
			}
			eb, err := jwt.NewParser().DecodeSegment(k.E)
			if err != nil {
				return nil, err
			}
			return &rsa.PublicKey{
				N: new(big.Int).SetBytes(nb),
				E: int(new(big.Int).SetBytes(eb).Int64()),
			}, nil
		}
		return nil, fmt.Errorf("kid %q not in JWKS", kid)
	}

	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, keyfunc, jwt.WithValidMethods([]string{"RS256"})); err != nil {
		t.Fatalf("verify token against JWKS: %v", err)
	}
	return claims
}

func TestNewRequiresUsers(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Fatal("expected error when Options.Users is empty")
	}
}

func TestDiscoveryPointsAtIssuer(t *testing.T) {
	t.Parallel()
	_, ts := NewTestServer(t, testOpts())

	var doc map[string]any
	getJSON(t, ts.URL+"/.well-known/openid-configuration", &doc)

	if doc["issuer"] != ts.URL {
		t.Fatalf("issuer=%v want %v", doc["issuer"], ts.URL)
	}
	for _, ep := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "revocation_endpoint"} {
		v, _ := doc[ep].(string)
		if !strings.HasPrefix(v, ts.URL+"/") {
			t.Errorf("%s=%q does not start with issuer %q", ep, v, ts.URL)
		}
	}
}

func TestAuthCodeRoundTrip(t *testing.T) {
	t.Parallel()
	_, ts := NewTestServer(t, testOpts())

	code := driveAuthCode(t, ts, "user-alice", "nonce-1")
	tr := exchangeCode(t, ts, code)

	if tr.TokenType != "Bearer" || tr.IDToken == "" || tr.AccessToken == "" || tr.RefreshToken == "" {
		t.Fatalf("incomplete token response: %+v", tr)
	}

	claims := verifyAgainstJWKS(t, ts, tr.IDToken)
	if claims["iss"] != ts.URL {
		t.Errorf("iss=%v want %v", claims["iss"], ts.URL)
	}
	if claims["sub"] != "user-alice" {
		t.Errorf("sub=%v want user-alice", claims["sub"])
	}
	if claims["nonce"] != "nonce-1" {
		t.Errorf("nonce=%v want nonce-1", claims["nonce"])
	}
	if claims["email"] != "alice@example.test" {
		t.Errorf("email=%v want alice@example.test", claims["email"])
	}

	// the code is one-time use
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://rp.example.test/callback"},
		"client_id":    {"test-client"},
	}
	postToken(t, ts, form, http.StatusBadRequest)
}

func TestTokenRejectsWrongClient(t *testing.T) {
	t.Parallel()
	_, ts := NewTestServer(t, testOpts())

	code := driveAuthCode(t, ts, "user-alice", "")
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://rp.example.test/callback"},
		"client_id":    {"wrong-client"},
	}
	postToken(t, ts, form, http.StatusUnauthorized)
}

func TestRefreshRoundTrip(t *testing.T) {
	t.Parallel()
	_, ts := NewTestServer(t, testOpts())

	code := driveAuthCode(t, ts, "user-bob", "")
	tr := exchangeCode(t, ts, code)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tr.RefreshToken},
		"client_id":     {"test-client"},
	}
	refreshed := postToken(t, ts, form, http.StatusOK)
	if refreshed.IDToken == "" || refreshed.AccessToken == "" {
		t.Fatalf("incomplete refresh response: %+v", refreshed)
	}
	claims := verifyAgainstJWKS(t, ts, refreshed.IDToken)
	if claims["sub"] != "user-bob" {
		t.Errorf("sub=%v want user-bob", claims["sub"])
	}
}

func TestRevokeMakesRefreshUnusable(t *testing.T) {
	t.Parallel()
	s, ts := NewTestServer(t, testOpts())

	code := driveAuthCode(t, ts, "user-carol", "")
	tr := exchangeCode(t, ts, code)

	resp, err := http.PostForm(ts.URL+"/revoke", url.Values{"token": {tr.RefreshToken}})
	if err != nil {
		t.Fatalf("POST /revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status=%d want 200", resp.StatusCode)
	}
	if got := s.RevokeCalls(); got != 1 {
		t.Errorf("RevokeCalls=%d want 1", got)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tr.RefreshToken},
		"client_id":     {"test-client"},
	}
	postToken(t, ts, form, http.StatusBadRequest)
}

func TestUserinfoValidatesToken(t *testing.T) {
	t.Parallel()
	s, ts := NewTestServer(t, testOpts())

	at, err := s.IssueAccessToken("user-dag", "openid profile")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	do := func(authz string) int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /userinfo: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var claims map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
				t.Fatalf("decode userinfo: %v", err)
			}
			if claims["sub"] != "user-dag" {
				t.Errorf("userinfo sub=%v want user-dag", claims["sub"])
			}
		}
		return resp.StatusCode
	}

	if got := do("Bearer " + at); got != http.StatusOK {
		t.Errorf("valid token: status=%d want 200", got)
	}
	if got := do(""); got != http.StatusUnauthorized {
		t.Errorf("no token: status=%d want 401", got)
	}
	if got := do("Bearer garbage.token.here"); got != http.StatusUnauthorized {
		t.Errorf("garbage token: status=%d want 401", got)
	}
	// token signed by a different fakeidp instance must be rejected
	other, _ := NewTestServer(t, testOpts())
	foreign, err := other.IssueAccessToken("user-dag", "openid")
	if err != nil {
		t.Fatalf("IssueAccessToken (other): %v", err)
	}
	if got := do("Bearer " + foreign); got != http.StatusUnauthorized {
		t.Errorf("foreign-signed token: status=%d want 401", got)
	}
}

func TestFailureInjection(t *testing.T) {
	t.Parallel()
	opts := testOpts()
	opts.ErrorRate = 1.0
	_, ts := NewTestServer(t, opts)

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 with ErrorRate=1", resp.StatusCode)
	}

	opts429 := testOpts()
	opts429.R429Rate = 1.0
	_, ts429 := NewTestServer(t, opts429)
	resp, err = http.Get(ts429.URL + "/jwks")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429 with R429Rate=1", resp.StatusCode)
	}
}

func TestKeyRotation(t *testing.T) {
	t.Parallel()
	opts := testOpts()
	opts.KeyKeep = 2
	s, ts := NewTestServer(t, opts)

	oldToken, err := s.IssueIDToken("user-alice", "openid", "")
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	oldKID := s.currentKey().KID

	newKey := s.RotateKeys()

	var jwks JWKS
	getJSON(t, ts.URL+"/jwks", &jwks)
	if len(jwks.Keys) != 2 {
		t.Fatalf("len(jwks.Keys)=%d want 2", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != newKey.KID {
		t.Errorf("jwks.Keys[0].Kid=%q want new kid %q", jwks.Keys[0].Kid, newKey.KID)
	}

	// token signed before rotation still verifies: old key still published
	verifyAgainstJWKS(t, ts, oldToken)

	// rotate again with KeyKeep=2 → the original key is dropped
	s.RotateKeys()
	getJSON(t, ts.URL+"/jwks", &jwks)
	if len(jwks.Keys) != 2 {
		t.Fatalf("len(jwks.Keys)=%d want 2 after second rotation", len(jwks.Keys))
	}
	for _, k := range jwks.Keys {
		if k.Kid == oldKID {
			t.Fatalf("old kid %q still published after falling out of keep window", oldKID)
		}
	}
}

func TestAddUserMidFlow(t *testing.T) {
	t.Parallel()
	s, ts := NewTestServer(t, testOpts())

	code := driveAuthCodeExpectStatus(t, ts, "user-eve", http.StatusUnauthorized)
	_ = code

	s.AddUser("user-eve", map[string]any{
		"email":          "eve@example.test",
		"email_verified": true,
		"name":           "Eve Evensen",
	})

	c := driveAuthCode(t, ts, "user-eve", "")
	tr := exchangeCode(t, ts, c)
	claims := verifyAgainstJWKS(t, ts, tr.IDToken)
	if claims["sub"] != "user-eve" || claims["email"] != "eve@example.test" {
		t.Fatalf("claims=%v", claims)
	}
}

func driveAuthCodeExpectStatus(t *testing.T, ts *httptest.Server, sub string, wantStatus int) string {
	t.Helper()
	authURL := fmt.Sprintf(
		"%s/authorize?client_id=test-client&redirect_uri=%s&login=%s",
		ts.URL, url.QueryEscape("https://rp.example.test/callback"), sub,
	)
	resp, err := noRedirect().Get(authURL)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("authorize status=%d want %d", resp.StatusCode, wantStatus)
	}
	return ""
}

func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	opts := testOpts()
	opts.KeyRotate = time.Hour
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSetDefaultLogin(t *testing.T) {
	t.Parallel()
	s, ts := NewTestServer(t, testOpts())
	s.SetDefaultLogin("user-carol")

	authURL := fmt.Sprintf(
		"%s/authorize?client_id=test-client&redirect_uri=%s&state=stateisatleast16chars",
		ts.URL, url.QueryEscape("https://rp.example.test/callback"),
	)
	resp, err := noRedirect().Get(authURL)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	tr := exchangeCode(t, ts, code)
	claims := verifyAgainstJWKS(t, ts, tr.IDToken)
	if claims["sub"] != "user-carol" {
		t.Fatalf("sub=%v want user-carol", claims["sub"])
	}
}
