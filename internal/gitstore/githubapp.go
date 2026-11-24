package gitstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sorend/passwordstore-operator/internal/printable"
)

const (
	// appTokenRefreshMargin is how long before its expiry an installation token is replaced.
	appTokenRefreshMargin = 5 * time.Minute
	// appJWTLifetime is the lifetime of the JWT that proves the identity of the App. GitHub
	// accepts at most ten minutes.
	appJWTLifetime = 9 * time.Minute
	// appJWTClockSkew is subtracted from the issue time of the JWT, so that a clock that is a
	// little ahead of the one of GitHub does not get the JWT rejected.
	appJWTClockSkew = time.Minute
	// maxAPIResponseSize bounds how much of a response of the GitHub API is read.
	maxAPIResponseSize = 1 << 20
)

// maxAPIErrorLength bounds how much of the message of an error response of the GitHub API is shown.
const maxAPIErrorLength = 256

// appTokenSource exchanges GitHub App credentials for installation tokens and caches them.
type appTokenSource struct {
	client *http.Client
	now    func() time.Time
	// guard limits the requests to the GitHub API, when the client is one that applies it.
	guard guard

	mu     sync.Mutex
	tokens map[string]appToken
}

type appToken struct {
	value     string
	expiresAt time.Time
}

func newAppTokenSource(client *http.Client, now func() time.Time, g guard) *appTokenSource {
	return &appTokenSource{client: client, now: now, guard: g, tokens: make(map[string]appToken)}
}

func (a *AppAuth) baseURL() string {
	if a.BaseURL == "" {
		return DefaultGitHubAPI
	}
	return strings.TrimRight(a.BaseURL, "/")
}

func (a *AppAuth) cacheKey() string {
	h := sha256.New()
	for _, part := range []string{
		a.baseURL(), strconv.FormatInt(a.AppID, 10), strconv.FormatInt(a.InstallationID, 10), string(a.PrivateKey),
	} {
		_, _ = fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// token returns a valid installation token, requesting a new one when needed.
func (s *appTokenSource) token(ctx context.Context, app *AppAuth) (string, error) {
	key := app.cacheKey()

	s.mu.Lock()
	cached, ok := s.tokens[key]
	s.mu.Unlock()
	if ok && s.now().Add(appTokenRefreshMargin).Before(cached.expiresAt) {
		return cached.value, nil
	}

	fresh, err := s.request(ctx, app)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	// A token that has expired is of no use any more. Without this a rotated key, or a removed
	// installation, would leave its token here for the life of the process.
	now := s.now()
	for k, t := range s.tokens {
		if !now.Before(t.expiresAt) {
			delete(s.tokens, k)
		}
	}
	s.tokens[key] = fresh
	s.mu.Unlock()
	return fresh.value, nil
}

// request asks GitHub for a new installation token. The token is limited to reading the
// contents of repositories, whatever else the App is allowed to do.
func (s *appTokenSource) request(ctx context.Context, app *AppAuth) (appToken, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(app.PrivateKey)
	if err != nil {
		return appToken{}, fmt.Errorf("parse github app private key: %w", err)
	}

	now := s.now()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    strconv.FormatInt(app.AppID, 10),
		IssuedAt:  jwt.NewNumericDate(now.Add(-appJWTClockSkew)),
		ExpiresAt: jwt.NewNumericDate(now.Add(appJWTLifetime)),
	}).SignedString(key)
	if err != nil {
		return appToken{}, fmt.Errorf("sign github app jwt: %w", err)
	}

	endpoint := fmt.Sprintf("%s/app/installations/%d/access_tokens", app.baseURL(), app.InstallationID)
	req, err := http.NewRequestWithContext(withGuard(ctx, s.guard), http.MethodPost, endpoint,
		strings.NewReader(`{"permissions":{"contents":"read"}}`))
	if err != nil {
		return appToken{}, fmt.Errorf("create github app token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "passwordstore-operator")

	resp, err := s.client.Do(req)
	if err != nil {
		return appToken{}, fmt.Errorf("request github app installation token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
	if err != nil {
		return appToken{}, fmt.Errorf("read github app installation token response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return appToken{}, fmt.Errorf("github returned %s when requesting an installation token for app %d, installation %d: %s",
			resp.Status, app.AppID, app.InstallationID, apiErrorMessage(body))
	}

	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		return appToken{}, fmt.Errorf("github returned an installation token response without a token")
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = now.Add(30 * time.Minute)
	}
	return appToken{value: out.Token, expiresAt: out.ExpiresAt}, nil
}

// apiErrorMessage extracts the message of an error response of the GitHub API. The API is at an
// address that the author of a store chooses, so what it says is shortened, and shown without
// anything that a terminal would act on.
func apiErrorMessage(body []byte) string {
	var out struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &out) == nil && out.Message != "" {
		return printable.String(out.Message, maxAPIErrorLength)
	}
	return "no error message"
}
