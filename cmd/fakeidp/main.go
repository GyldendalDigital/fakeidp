// Command fakeidp runs the mock OpenID Connect provider as a standalone
// HTTP server, configured via environment variables and flags. User
// personas are loaded from a state file or generated via the persona API
// (network I/O lives here, not in the library).
package main

import (
	crypto_rand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/GyldendalDigital/fakeidp"
)

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

func generateAdditionalUsers(users map[string]map[string]any, lang string, n int) (int, error) {
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
		sub := "user-" + lang + "-" + randomSuffix()

		users[sub] = map[string]any{
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

func randomSuffix() string {
	b := make([]byte, 8)
	if _, err := crypto_rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
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

func generateUsers(total int) (map[string]map[string]any, error) {
	if total < 0 {
		return nil, fmt.Errorf("user count must be >= 0")
	}
	users := make(map[string]map[string]any)
	counts := distributeCount(total, len(defaultUserLanguages))
	generated := 0
	for i, lang := range defaultUserLanguages {
		added, err := generateAdditionalUsers(users, lang, counts[i])
		if err != nil {
			return nil, err
		}
		generated += added
	}
	if generated != total {
		return nil, fmt.Errorf("generated %d users, expected %d", generated, total)
	}
	return users, nil
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

func loadOrGenerateUsers(cfg startupConfig) (map[string]map[string]any, error) {
	if cfg.UserStatePath != "" {
		exists, err := fileExists(cfg.UserStatePath)
		if err != nil {
			return nil, fmt.Errorf("stat userstate file: %w", err)
		}
		if exists {
			users, err := loadUserState(cfg.UserStatePath)
			if err != nil {
				return nil, err
			}
			slog.Info("Loaded users from userstate file", "path", cfg.UserStatePath, "count", len(users))
			return users, nil
		}
	}

	users, err := generateUsers(cfg.UserCount)
	if err != nil {
		return nil, err
	}
	slog.Info("Generated users", "count", len(users))

	if cfg.UserStatePath != "" {
		if err := saveUserState(cfg.UserStatePath, users); err != nil {
			return nil, err
		}
		slog.Info("Saved generated users to userstate file", "path", cfg.UserStatePath, "count", len(users))
	}
	return users, nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)
	startupCfg := parseStartupConfig()

	users, err := loadOrGenerateUsers(startupCfg)
	if err != nil {
		slog.Error("Failed to initialize users", "error", err)
		os.Exit(1)
	}

	port, _ := strconv.Atoi(mustEnv("PORT", "8080"))
	opts := fakeidp.Options{
		Issuer:       mustEnv("OIDC_ISSUER", "http://localhost:8080"),
		ClientID:     mustEnv("OIDC_CLIENT_ID", "demo-client"),
		ClientSecret: mustEnv("OIDC_CLIENT_SECRET", ""),
		Users:        users,
		KeyRotate:    parseDurationEnv("KEY_ROTATE_EVERY", "24h"),
		KeyKeep:      func() int { v, _ := strconv.Atoi(mustEnv("KEY_KEEP", "3")); return v }(),
		LatencyP95:   parseDurationEnv("LATENCY_P95", "0s"),
		ErrorRate:    parseFloatEnv("ERROR_RATE", "0"),
		R429Rate:     parseFloatEnv("R429_RATE", "0"),
		Seed:         uint64(time.Now().UnixNano()),
		Logger:       logger,
		DebugTokens:  mustEnv("DEBUG_TOKENS", "false") == "true",
	}

	s, err := fakeidp.New(opts)
	if err != nil {
		slog.Error("Failed to construct server", "error", err)
		os.Exit(1)
	}
	defer s.Close()

	addr := fmt.Sprintf(":%d", port)
	slog.Info("Mock IdP listening", "address", addr, "issuer", opts.Issuer)
	slog.Info("Configuration",
		"client_id", opts.ClientID,
		"key_rotate", opts.KeyRotate.String(),
		"latency_p95", opts.LatencyP95.String(),
		"error_rate", opts.ErrorRate,
		"r429_rate", opts.R429Rate,
		"debug_tokens", opts.DebugTokens,
		"userstate", startupCfg.UserStatePath,
		"user_count", len(users),
	)

	if pk := os.Getenv("PRINT_PRIVATE_KEY"); pk == "1" {
		kid, pem := s.CurrentKeyPEM()
		slog.Info("Current private key", "kid", kid, "pem", pem)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("Server exited", "error", err)
	}
}
