package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// NewRSAKeyPEM generates an RSA private key in the PKCS#1 PEM format that GitHub hands out for
// Apps.
func NewRSAKeyPEM(t TB) (pemKey []byte, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), key
}

// FakeGitHubApp implements the one endpoint of the GitHub API that the operator uses for GitHub
// Apps: creating an installation access token. It checks the JWT like GitHub does.
type FakeGitHubApp struct {
	// URL is the base URL of the API.
	URL string

	appID          int64
	installationID int64
	publicKey      *rsa.PublicKey
	server         *httptest.Server

	mu       sync.Mutex
	issued   []string
	requests int
	// failWith, when set, is returned as the status and message of every request.
	failStatus  int
	failMessage string
	// lifetime of the tokens that are issued.
	lifetime time.Duration
	now      func() time.Time
}

// NewFakeGitHubApp starts the fake for one App installation. Tokens last for an hour.
func NewFakeGitHubApp(t TB, appID, installationID int64, publicKey *rsa.PublicKey) *FakeGitHubApp {
	t.Helper()
	f := &FakeGitHubApp{appID: appID, installationID: installationID, publicKey: publicKey, lifetime: time.Hour, now: time.Now}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	f.URL = f.server.URL
	return f
}

// Fail makes the fake answer every request with the status and message.
func (f *FakeGitHubApp) Fail(status int, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failStatus, f.failMessage = status, message
}

// SetClock makes the fake use now as the current time, for the claims of the JWT and for the
// expiry of the tokens it issues. It must be the clock that the client under test uses.
func (f *FakeGitHubApp) SetClock(now func() time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = now
}

// SetTokenLifetime sets how long the tokens that are issued from now on are valid.
func (f *FakeGitHubApp) SetTokenLifetime(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lifetime = d
}

// Requests returns how many requests have been made.
func (f *FakeGitHubApp) Requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// IsValidToken reports whether the token was issued by the fake.
func (f *FakeGitHubApp) IsValidToken(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.issued, token)
}

// LastToken returns the token that was issued last.
func (f *FakeGitHubApp) LastToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.issued) == 0 {
		return ""
	}
	return f.issued[len(f.issued)-1]
}

func (f *FakeGitHubApp) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	failStatus, failMessage, lifetime, now := f.failStatus, f.failMessage, f.lifetime, f.now
	f.mu.Unlock()

	reply := func(status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	deny := func(status int, format string, args ...any) {
		reply(status, map[string]string{"message": fmt.Sprintf(format, args...)})
	}

	if failStatus != 0 {
		deny(failStatus, "%s", failMessage)
		return
	}
	wantPath := fmt.Sprintf("/app/installations/%d/access_tokens", f.installationID)
	if r.Method != http.MethodPost || r.URL.Path != wantPath {
		deny(http.StatusNotFound, "Not Found: %s %s", r.Method, r.URL.Path)
		return
	}
	if r.Header.Get("Accept") != "application/vnd.github+json" {
		deny(http.StatusBadRequest, "missing Accept header")
		return
	}

	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		deny(http.StatusUnauthorized, "A JSON web token could not be decoded")
		return
	}
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return f.publicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(strconv.FormatInt(f.appID, 10)),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(now),
	)
	if err != nil {
		deny(http.StatusUnauthorized, "Bad credentials: %v", err)
		return
	}
	if claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 10*time.Minute+time.Minute {
		deny(http.StatusUnauthorized, "'Expiration time' claim ('exp') must be a numeric value representing the future time at which the assertion expires")
		return
	}

	var body struct {
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Permissions["contents"] != "read" || len(body.Permissions) != 1 {
		deny(http.StatusUnprocessableEntity, "the token must be limited to contents: read, got %v", body.Permissions)
		return
	}

	f.mu.Lock()
	token := fmt.Sprintf("ghs_test_token_%d", len(f.issued)+1)
	f.issued = append(f.issued, token)
	f.mu.Unlock()
	reply(http.StatusCreated, map[string]any{
		"token":      token,
		"expires_at": now().Add(lifetime).UTC().Format(time.RFC3339),
	})
}
