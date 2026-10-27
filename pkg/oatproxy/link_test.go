package oatproxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
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

// linkAndRedeem links a PAR for jkt to root and redeems the code like the
// downstream client would, returning the session as later loaded.
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
	if _, err := o.Token(context.Background(), &TokenRequest{GrantType: "authorization_code", Code: res.Code, CodeVerifier: testVerifier}, "", session); err != nil {
		t.Fatalf("Token: %v", err)
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
