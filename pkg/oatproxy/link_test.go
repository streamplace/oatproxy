package oatproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

// testLinkProxy is testIntrospectProxy backed by an in-memory session store.
func testLinkProxy(t *testing.T) (*OATProxy, map[string]*OAuthSession) {
	t.Helper()
	o := testIntrospectProxy(t)
	o.slog = slog.New(slog.DiscardHandler)
	store := map[string]*OAuthSession{}
	save := func(id string, s *OAuthSession) error {
		cp := *s
		store[id] = &cp
		return nil
	}
	o.createOAuthSession = save
	o.updateOAuthSession = save
	o.userGetOAuthSession = func(id string) (*OAuthSession, error) {
		s, ok := store[id]
		if !ok {
			return nil, nil
		}
		cp := *s
		return &cp, nil
	}
	o.lock = func(string) (func(), error) { return func() {}, nil }
	return o, store
}

const testVerifier = "test-verifier"

func addRoot(t *testing.T, store map[string]*OAuthSession, scope string) *OAuthSession {
	t.Helper()
	key, err := jwk.FromRaw(mustECDSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	root := &OAuthSession{
		DID:                         "did:plc:root",
		Handle:                      "root.example.com",
		PDSUrl:                      "https://pds.example.com",
		DownstreamDPoPJKT:           "root-jkt",
		DownstreamAccessToken:       "root-access",
		UpstreamDPoPPrivateJWK:      string(keyJSON),
		UpstreamAccessToken:         "upstream-access",
		UpstreamRefreshToken:        "upstream-refresh",
		UpstreamAccessTokenExp:      &exp,
		UpstreamAccessTokenLifetime: 3600,
		UpstreamScope:               scope,
		DownstreamScope:             scope,
	}
	store[root.DownstreamDPoPJKT] = root
	return root
}

func addPAR(store map[string]*OAuthSession, jkt, scope string) string {
	h := sha256.Sum256([]byte(testVerifier))
	urn := makeURN(jkt)
	store[jkt] = &OAuthSession{
		DownstreamDPoPJKT:       jkt,
		DownstreamPARRequestURI: urn,
		DownstreamCodeChallenge: base64.RawURLEncoding.EncodeToString(h[:]),
		DownstreamState:         "client-state",
		DownstreamScope:         scope,
	}
	return urn
}

// linkAndRedeem links a PAR for jkt to root and redeems the code (past
// Token's DPoP and client checks), returning the session as later loaded.
func linkAndRedeem(t *testing.T, o *OATProxy, store map[string]*OAuthSession, jkt string, approver *OAuthSession) *OAuthSession {
	t.Helper()
	urn := addPAR(store, jkt, "atproto blob:*/* include:place.stream.authFull")
	res, err := o.LinkSession(context.Background(), urn, approver)
	if err != nil {
		t.Fatalf("LinkSession: %v", err)
	}
	if res.State != "client-state" || res.Iss != "https://proxy.example.com" || res.Code == "" {
		t.Fatalf("unexpected authorization response %+v", res)
	}
	session, err := o.getOAuthSession(jkt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.AccessToken(context.Background(), &TokenRequest{GrantType: "authorization_code", Code: res.Code, CodeVerifier: testVerifier}, session); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	session, err = o.getOAuthSession(jkt)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestLinkSession(t *testing.T) {
	o, store := testLinkProxy(t)
	root := addRoot(t, store, "atproto blob:*/*")

	child := linkAndRedeem(t, o, store, "child-jkt", root)
	if child.Status() != OAuthSessionStateReady {
		t.Fatalf("status = %s, want ready", child.Status())
	}
	if child.DID != "did:plc:root" || child.UpstreamAccessToken != "upstream-access" || child.UpstreamDPoPPrivateJWK != root.UpstreamDPoPPrivateJWK {
		t.Errorf("child did not borrow root's upstream session: %+v", child)
	}
	if child.DownstreamAccessToken == "root-access" || child.DownstreamDPoPJKT != "child-jkt" {
		t.Error("child should keep its own downstream state")
	}
	// the child asked for more than the root has; it gets only the overlap
	if got := child.GrantedScope(); got != "atproto blob:*/*" {
		t.Errorf("granted scope = %q, want the root's", got)
	}

	// the child row never stores upstream state, even after the token
	// endpoint saved the merged session
	row := store["child-jkt"]
	if row.UpstreamAccessToken != "" || row.UpstreamRefreshToken != "" || row.UpstreamDPoPPrivateJWK != "" || row.UpstreamAccessTokenExp != nil {
		t.Errorf("child row holds upstream state: %+v", row)
	}

	// approving from a linked session links to the same root
	grandchild := linkAndRedeem(t, o, store, "grandchild-jkt", child)
	if store["grandchild-jkt"].UpstreamJKT != "root-jkt" || grandchild.UpstreamAccessToken != "upstream-access" {
		t.Errorf("grandchild should link to the root, got %q", store["grandchild-jkt"].UpstreamJKT)
	}
}

func TestLinkSessionRejects(t *testing.T) {
	o, store := testLinkProxy(t)
	root := addRoot(t, store, "")
	urn := addPAR(store, "child-jkt", "atproto")
	if _, err := o.LinkSession(context.Background(), urn, root); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	store["revoked-jkt"] = &OAuthSession{DownstreamDPoPJKT: "revoked-jkt", DownstreamAccessToken: "x", UpstreamDPoPPrivateJWK: "x", RevokedAt: &now}
	pending := addPAR(store, "pending-jkt", "atproto")

	for name, tc := range map[string]struct {
		urn      string
		approver *OAuthSession
	}{
		"already used":    {urn, root},
		"short garbage":   {urnPrefix + "abc", root},
		"wrong prefix":    {"urn:nope", root},
		"unknown session": {makeURN("nobody-jkt"), root},
		"stale uri":       {makeURN("pending-jkt"), root},
		"revoked root":    {pending, store["revoked-jkt"]},
		"self":            {pending, store["pending-jkt"]},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := o.LinkSession(context.Background(), tc.urn, tc.approver); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestLinkedSessionFollowsRoot(t *testing.T) {
	o, store := testLinkProxy(t)
	root := addRoot(t, store, "")
	linkAndRedeem(t, o, store, "child-jkt", root)

	// the root logging out leaves the upstream session, and the child, working
	now := time.Now()
	store["root-jkt"].DownstreamRevokedAt = &now
	child, err := o.getOAuthSession("child-jkt")
	if err != nil {
		t.Fatal(err)
	}
	if child.Status() != OAuthSessionStateReady {
		t.Errorf("status after root logout = %s, want ready", child.Status())
	}

	store["root-jkt"].RevokedAt = &now
	child, err = o.getOAuthSession("child-jkt")
	if err != nil {
		t.Fatal(err)
	}
	if child.Status() != OAuthSessionStateRejected {
		t.Errorf("status after root revocation = %s, want rejected", child.Status())
	}

	delete(store, "root-jkt")
	child, err = o.getOAuthSession("child-jkt")
	if err != nil {
		t.Fatal(err)
	}
	if child.Status() != OAuthSessionStateRejected {
		t.Errorf("status without root = %s, want rejected", child.Status())
	}
}

func TestLinkedSessionNonceWriteBack(t *testing.T) {
	o, store := testLinkProxy(t)
	root := addRoot(t, store, "")
	child := linkAndRedeem(t, o, store, "child-jkt", root)

	client, err := o.GetXrpcClient(child)
	if err != nil {
		t.Fatal(err)
	}
	client.client.OnDpopPdsNonceChanged(child.DID, "new-nonce")
	if store["root-jkt"].UpstreamDPoPNonce != "new-nonce" {
		t.Errorf("root nonce = %q, want new-nonce", store["root-jkt"].UpstreamDPoPNonce)
	}
	if store["child-jkt"].UpstreamDPoPNonce != "" {
		t.Error("nonce written to the child row")
	}
}

// A linked session's scope is fixed when it's linked. Its client could push a
// new authorization request with the same DPoP key, which would otherwise
// rewrite that scope and widen the session's grant without approval.
func TestLinkedSessionRejectsNewPAR(t *testing.T) {
	o, store := testLinkProxy(t)
	root := addRoot(t, store, "atproto blob:*/* include:place.stream.authFull repo:app.bsky.feed.post")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.FromRaw(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	var pubMap map[string]any
	if err := json.Unmarshal(pubJSON, &pubMap); err != nil {
		t.Fatal(err)
	}
	proof := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": "POST",
		"htu": "https://proxy.example.com/oauth/par",
		"iat": time.Now().Unix(),
		"jti": "new-par",
	})
	proof.Header["typ"] = "dpop+jwt"
	proof.Header["jwk"] = pubMap
	dpopHeader, err := proof.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	jkt, _, err := getJKT(dpopHeader)
	if err != nil {
		t.Fatal(err)
	}

	child := linkAndRedeem(t, o, store, jkt, root)
	granted := child.GrantedScope()
	if granted == root.UpstreamScope {
		t.Fatal("test needs a child granted less than the root")
	}

	c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/oauth/par", nil), httptest.NewRecorder())
	_, err = o.NewPAR(context.Background(), c, &PAR{Scope: root.UpstreamScope}, dpopHeader)
	if err == nil {
		t.Fatal("a new PAR with a linked session's key should be refused")
	}
	again, err := o.getOAuthSession(jkt)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.GrantedScope(); got != granted {
		t.Errorf("granted scope = %q, want it unchanged at %q", got, granted)
	}
}

const fullGrant = "atproto blob:*/* repo:app.bsky.feed.post"

// linkWith links a PAR asking for requested to approver, as LinkSession does
// for a QR approval, and returns the linked session as later loaded.
func linkWith(t *testing.T, o *OATProxy, store map[string]*OAuthSession, jkt, requested string, approver *OAuthSession) *OAuthSession {
	t.Helper()
	if _, err := o.LinkSession(context.Background(), addPAR(store, jkt, requested), approver); err != nil {
		t.Fatalf("LinkSession: %v", err)
	}
	session, err := o.getOAuthSession(jkt)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestLinkSessionCapsScopeByApproverAndRoot(t *testing.T) {
	o, store := testLinkProxy(t)
	o.scope = fullGrant
	root := addRoot(t, store, fullGrant)

	narrow := linkWith(t, o, store, "narrow-jkt", "atproto blob:*/*", root)
	if got := narrow.GrantedScope(); got != "atproto blob:*/*" {
		t.Fatalf("narrow granted %q", got)
	}
	// an approver limited to blob can't hand out the post scope its root has
	child := linkWith(t, o, store, "child-jkt", fullGrant, narrow)
	if got := child.GrantedScope(); got != "atproto blob:*/*" {
		t.Errorf("grandchild granted %q, want its approver's grant", got)
	}
	// and the root's current grant caps an approver that holds more
	store["root-jkt"].UpstreamScope = "atproto"
	approver, err := o.getOAuthSession("narrow-jkt")
	if err != nil {
		t.Fatal(err)
	}
	only := linkWith(t, o, store, "only-jkt", fullGrant, approver)
	if got := only.GrantedScope(); got != "atproto" {
		t.Errorf("granted %q, want the root's narrowed grant", got)
	}

	// nothing in common with the approver's grant is refused, not granted wide open
	if _, err := o.LinkSession(context.Background(), addPAR(store, "none-jkt", "repo:app.bsky.feed.post"), approver); err == nil {
		t.Error("expected an error when the approver can grant none of the request")
	}
}

func TestLinkedSessionGrantFollowsRootScope(t *testing.T) {
	o, store := testLinkProxy(t)
	root := addRoot(t, store, fullGrant)
	child := linkWith(t, o, store, "child-jkt", fullGrant, root)
	if got := child.GrantedScope(); got != fullGrant {
		t.Fatalf("granted %q", got)
	}

	// the upstream refresh returned fewer scopes
	store["root-jkt"].UpstreamScope = "atproto blob:*/*"
	child, err := o.getOAuthSession("child-jkt")
	if err != nil {
		t.Fatal(err)
	}
	if got := o.grantedScope(child); got != "atproto blob:*/*" || child.HasScope("repo:app.bsky.feed.post") {
		t.Errorf("granted %q after the root lost a scope", got)
	}

	// a root that no longer holds atproto leaves nothing to share
	store["root-jkt"].UpstreamScope = "blob:*/*"
	child, err = o.getOAuthSession("child-jkt")
	if err != nil {
		t.Fatal(err)
	}
	if child.Status() != OAuthSessionStateRejected {
		t.Errorf("status = %s, want rejected", child.Status())
	}
}

func TestLinkSessionIssuerIsOrigin(t *testing.T) {
	o, store := testLinkProxy(t)
	o.baseURL = "http://127.0.0.1:38080/"
	root := addRoot(t, store, "")
	res, err := o.LinkSession(context.Background(), addPAR(store, "child-jkt", "atproto"), root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Iss != "http://127.0.0.1:38080" {
		t.Errorf("iss = %q", res.Iss)
	}
}

func TestCheckPendingPAR(t *testing.T) {
	o, store := testLinkProxy(t)
	root := addRoot(t, store, "")
	urn := addPAR(store, "child-jkt", "atproto")

	for name, tc := range map[string]struct {
		uri  string
		want bool
	}{
		"pending":   {urn, true},
		"garbage":   {"urn:nope", false},
		"unknown":   {makeURN("nobody-jkt"), false},
		"stale uri": {makeURN("child-jkt"), false},
	} {
		got, err := o.CheckPendingPAR(context.Background(), tc.uri)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", name, got, err, tc.want)
		}
	}

	if _, err := o.LinkSession(context.Background(), urn, root); err != nil {
		t.Fatal(err)
	}
	if got, err := o.CheckPendingPAR(context.Background(), urn); err != nil || got {
		t.Errorf("linked: got %v, %v; want false", got, err)
	}

	o.userGetOAuthSession = func(string) (*OAuthSession, error) { return nil, errors.New("store down") }
	if got, err := o.CheckPendingPAR(context.Background(), urn); err == nil || got {
		t.Errorf("store error: got %v, %v", got, err)
	}
}

// With the real store (whose updates skip zero fields) a stray write of the
// merged session would leave the root's credentials in the child row for good.
func TestNonceMiddlewareKeepsRootStateOutOfLinkedRow(t *testing.T) {
	o, db, key := chainProxy(t)
	rootKey, err := json.Marshal(key)
	require.NoError(t, err)
	exp := time.Now().Add(time.Hour)
	require.NoError(t, db.Create(&OAuthSession{
		DID: "did:plc:root", PDSUrl: "https://station.example.com", DownstreamDPoPJKT: "root-jkt",
		DownstreamAccessToken: "root-access", DownstreamDPoPNoncePad: makeNoncePad(),
		UpstreamDPoPPrivateJWK: string(rootKey), UpstreamAccessToken: "upstream-access", UpstreamRefreshToken: "upstream-refresh",
		UpstreamAccessTokenExp: &exp, UpstreamAccessTokenLifetime: 3600, UpstreamScope: "atproto",
	}).Error)

	childKey, err := jwk.FromRaw(mustECDSAKey(t))
	require.NoError(t, err)
	endpoint := localOrigin + "/oauth/token"
	jkt, _, err := getJKT(chainProof(t, childKey, "POST", endpoint, "", ""))
	require.NoError(t, err)
	pad := makeNoncePad()
	urn := makeURN(jkt)
	require.NoError(t, db.Create(&OAuthSession{DownstreamDPoPJKT: jkt, DownstreamDPoPNoncePad: pad, DownstreamPARRequestURI: urn, DownstreamScope: "atproto"}).Error)
	root, err := o.getOAuthSession("root-jkt")
	require.NoError(t, err)
	_, err = o.LinkSession(t.Context(), urn, root)
	require.NoError(t, err)

	proof := chainProof(t, childKey, "POST", endpoint, generateValidNonces(pad, time.Now())[0], "")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	req.Header.Set("DPoP", proof)
	c := echo.New().NewContext(req, httptest.NewRecorder())
	require.NoError(t, o.DPoPNonceMiddleware(func(echo.Context) error { return nil })(c))

	var row OAuthSession
	require.NoError(t, db.First(&row, "downstream_dpop_jkt = ?", jkt).Error)
	require.NotEmpty(t, row.DownstreamJTICache, "the middleware still records the proof")
	require.Empty(t, row.UpstreamAccessToken)
	require.Empty(t, row.UpstreamRefreshToken)
	require.Empty(t, row.UpstreamDPoPPrivateJWK)
}

// A PAR racing LinkSession for the same key must wait for it, then be refused,
// instead of overwriting the scope the approver just granted.
func TestNewPARWaitsForLinkSession(t *testing.T) {
	o, db, key := chainProxy(t)
	meta, err := o.GetDownstreamMetadata(localOrigin + "/login")
	require.NoError(t, err)
	par := &PAR{ClientID: meta.ClientID, RedirectURI: meta.RedirectURIs[0], Scope: testFullScope,
		LoginHint: "did:plc:account", State: "state", CodeChallenge: "challenge", CodeChallengeMethod: "S256", ResponseType: "code"}
	endpoint := localOrigin + "/oauth/par"
	c := o.Echo.NewContext(httptest.NewRequest(http.MethodPost, "/oauth/par", nil), httptest.NewRecorder())
	jkt, _, err := getJKT(chainProof(t, key, "POST", endpoint, "", ""))
	require.NoError(t, err)
	_, err = o.NewPAR(t.Context(), c, par, chainProof(t, key, "POST", endpoint, "", ""))
	require.ErrorIs(t, err, ErrFirstNonce)
	nonce := c.Response().Header().Get("DPoP-Nonce")
	_, err = o.NewPAR(t.Context(), c, par, chainProof(t, key, "POST", endpoint, nonce, ""))
	require.NoError(t, err)

	unlock, err := o.lock(jkt)
	require.NoError(t, err)
	done := make(chan error, 1)
	par.Scope = "atproto blob:*/*"
	go func() {
		_, err := o.NewPAR(t.Context(), c, par, chainProof(t, key, "POST", endpoint, nonce, ""))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("NewPAR ran while the session was locked: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	require.NoError(t, db.Model(&OAuthSession{}).Where("downstream_dpop_jkt = ?", jkt).
		Updates(map[string]any{"upstream_jkt": "root-jkt", "downstream_scope": "atproto"}).Error)
	unlock()
	require.Error(t, <-done)

	var row OAuthSession
	require.NoError(t, db.First(&row, "downstream_dpop_jkt = ?", jkt).Error)
	require.Equal(t, "atproto", row.DownstreamScope)
}
