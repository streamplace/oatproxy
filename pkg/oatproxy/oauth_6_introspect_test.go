package oatproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func testIntrospectProxy(t *testing.T) *OATProxy {
	t.Helper()
	raw, err := jwk.FromRaw(mustECDSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return &OATProxy{
		host:          "proxy.example.com",
		scope:         testFullScope,
		downstreamJWK: raw,
		clientMetadata: &OAuthClientMetadata{
			RedirectURIs: []string{"https://proxy.example.com/login"},
			Scope:        testFullScope,
		},
	}
}

func introspect(t *testing.T, o *OATProxy, session *OAuthSession, authToken, formToken string) *IntrospectionResponse {
	t.Helper()
	e := echo.New()
	body := ""
	if formToken != "" {
		body = fmt.Sprintf("token=%s", formToken)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	if authToken != "" {
		req.Header.Set("Authorization", "DPoP "+authToken)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if session != nil {
		c.Set("session", session)
	}
	if err := o.HandleOAuthIntrospect(c); err != nil {
		t.Fatalf("HandleOAuthIntrospect: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	resp := &IntrospectionResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestIntrospect(t *testing.T) {
	o := testIntrospectProxy(t)
	session := &OAuthSession{
		DID:               "did:plc:test123",
		DownstreamDPoPJKT: "test-jkt",
	}
	token, err := o.generateJWT(session)
	if err != nil {
		t.Fatal(err)
	}
	session.DownstreamAccessToken = token
	session.DownstreamScope = "atproto blob:*/* include:place.stream.authFull"
	session.UpstreamScope = "atproto blob:*/* include:place.stream.authFull"
	// make the session read as ready
	session.UpstreamDPoPPrivateJWK = "unused"
	session.DownstreamAuthorizationCode = "unused"

	resp := introspect(t, o, session, token, "")
	if !resp.Active {
		t.Fatal("expected active token")
	}
	if resp.Scope != "atproto blob:*/* include:place.stream.authFull" {
		t.Errorf("scope = %q", resp.Scope)
	}
	if resp.Sub != "did:plc:test123" {
		t.Errorf("sub = %q", resp.Sub)
	}
	if resp.Iss != "https://proxy.example.com" {
		t.Errorf("iss = %q", resp.Iss)
	}
	if resp.TokenType != "DPoP" {
		t.Errorf("token_type = %q", resp.TokenType)
	}
	if resp.Exp == 0 || time.Unix(resp.Exp, 0).Before(time.Now()) {
		t.Errorf("exp = %d, want future timestamp", resp.Exp)
	}

	// explicit token param matching the caller's own token is allowed
	resp = introspect(t, o, session, token, token)
	if !resp.Active {
		t.Error("expected active for explicit own token")
	}

	// legacy session with no recorded scope reports the configured scope
	legacy := *session
	legacy.DownstreamScope = ""
	legacy.UpstreamScope = ""
	resp = introspect(t, o, &legacy, token, "")
	if !resp.Active || resp.Scope != testFullScope {
		t.Errorf("legacy scope = %q active=%v, want configured scope, active", resp.Scope, resp.Active)
	}

	// introspecting someone else's token reports inactive
	resp = introspect(t, o, session, token, "some-other-token")
	if resp.Active {
		t.Error("expected inactive for foreign token")
	}

	// stale token (not the session's current one) reports inactive
	otherToken, err := o.generateJWT(session)
	if err != nil {
		t.Fatal(err)
	}
	resp = introspect(t, o, session, otherToken, "")
	if resp.Active {
		t.Error("expected inactive for stale token")
	}

	// revoked session reports inactive
	now := time.Now()
	revoked := *session
	revoked.DownstreamRevokedAt = &now
	resp = introspect(t, o, &revoked, token, "")
	if resp.Active {
		t.Error("expected inactive for revoked session")
	}

	// no session in context (unauthenticated) reports inactive
	resp = introspect(t, o, nil, token, "")
	if resp.Active {
		t.Error("expected inactive without a session")
	}
}

func mustECDSAKey(t *testing.T) any {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
