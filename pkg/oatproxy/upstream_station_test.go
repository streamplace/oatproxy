package oatproxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const localOrigin = "http://127.0.0.1:38080"

func chainProxy(t *testing.T) (*OATProxy, *gorm.DB, jwk.Key) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.AutoMigrate(&OAuthSession{}))
	key, err := jwk.FromRaw(mustECDSAKey(t))
	require.NoError(t, err)
	o := New(&Config{
		Host: "127.0.0.1:38080", BaseURL: localOrigin,
		UpstreamURL: "https://station.example.com", Scope: testFullScope,
		UpstreamJWK: key, DownstreamJWK: key,
		ClientMetadata:     &OAuthClientMetadata{Scope: testFullScope, RedirectURIs: []string{localOrigin + "/login"}},
		CreateOAuthSession: func(_ string, session *OAuthSession) error { return db.Create(session).Error },
		UpdateOAuthSession: func(id string, session *OAuthSession) error {
			return db.Model(&OAuthSession{}).Where("downstream_dpop_jkt = ?", id).Updates(session).Error
		},
		GetOAuthSession: func(id string) (*OAuthSession, error) {
			var session OAuthSession
			err := db.First(&session, "downstream_dpop_jkt = ?", id).Error
			if err == gorm.ErrRecordNotFound {
				return nil, nil
			}
			return &session, err
		},
	})
	return o, db, key
}

func chainProof(t *testing.T, key jwk.Key, method, endpoint, nonce, accessToken string) string {
	t.Helper()
	pub, err := key.PublicKey()
	require.NoError(t, err)
	encoded, err := json.Marshal(pub)
	require.NoError(t, err)
	var pubMap map[string]any
	require.NoError(t, json.Unmarshal(encoded, &pubMap))
	claims := jwt.MapClaims{"jti": uuid.NewString(), "htm": method, "htu": endpoint, "iat": time.Now().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(hash[:])
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = pubMap
	var raw any
	require.NoError(t, key.Raw(&raw))
	proof, err := token.SignedString(raw)
	require.NoError(t, err)
	return proof
}

func TestExplicitOriginAndLocalClientMetadata(t *testing.T) {
	o, _, _ := chainProxy(t)
	for _, redirect := range []string{localOrigin + "/login", localOrigin + "/app-return/streamplace"} {
		meta, err := o.GetDownstreamMetadata(redirect)
		require.NoError(t, err)
		require.Equal(t, []string{redirect}, meta.RedirectURIs)
		require.Equal(t, redirect, mustParseURL(t, meta.ClientID).Query().Get("redirect_uri"))
		require.Equal(t, "none", meta.TokenEndpointAuthMethod)
	}
	for _, redirect := range []string{"http://127.0.0.1:9999/login", "https://evil.example/login", localOrigin + "/unregistered"} {
		_, err := o.GetDownstreamMetadata(redirect)
		require.Error(t, err)
	}
	require.Equal(t, localOrigin+"/oauth/token", o.authServerURL(&OAuthSession{UpstreamAuthServerURL: "https://station.example.com"}, "/oauth/token").String())
	require.Equal(t, localOrigin+"/xrpc/test", o.pdsServerURL(&OAuthSession{PDSUrl: "https://station.example.com"}, "/xrpc/test").String())
	meta := o.GetUpstreamMetadata()
	require.Equal(t, "none", meta.TokenEndpointAuthMethod)
	require.Equal(t, []string{localOrigin + "/oauth/return"}, meta.RedirectURIs)
	client, err := o.GetOauthClient()
	require.NoError(t, err)
	require.True(t, client.IsPublic())
	station := testIntrospectProxy(t)
	station.upstreamJWK = o.upstreamJWK
	require.Equal(t, "private_key_jwt", station.GetUpstreamMetadata().TokenEndpointAuthMethod)
	_, err = station.downstreamMetadata(meta.ClientID, meta.RedirectURIs[0])
	require.NoError(t, err, "station must accept the local node's public client")
	for _, redirect := range []string{"http://localhost:38080/oauth/return", "http://evil.example:38080/oauth/return", "http://127.0.0.1:38080/oauth/return#fragment"} {
		_, err := station.downstreamMetadata(station.publicClientID(redirect).String(), redirect)
		require.Error(t, err)
	}
	for _, origin := range []string{"http://evil.example", "http://localhost:38080", "https://user:pass@station.example", "https://station.example/path", "https://station.example?next=evil"} {
		require.Error(t, validateOrigin(origin, true))
	}
	require.Error(t, validateOrigin(localOrigin, false), "upstream stations cannot use HTTP")
}

func TestLocalClientDeclaredScopeDoesNotRestrictRequestedSubset(t *testing.T) {
	local, _, _ := chainProxy(t)
	meta := local.GetUpstreamMetadata()
	station, db, key := chainProxy(t)
	station.baseURL = "https://station.example.com"
	station.scope = "atproto"
	par := &PAR{ClientID: meta.ClientID, RedirectURI: meta.RedirectURIs[0], Scope: "atproto",
		LoginHint: "did:plc:account", State: "local-state", CodeChallenge: "challenge", CodeChallengeMethod: "S256", ResponseType: "code"}
	c := station.Echo.NewContext(httptest.NewRequest(http.MethodPost, "/oauth/par", nil), httptest.NewRecorder())
	endpoint := station.origin() + "/oauth/par"
	_, err := station.NewPAR(t.Context(), c, par, chainProof(t, key, "POST", endpoint, "", ""))
	require.ErrorIs(t, err, ErrFirstNonce)
	nonce := c.Response().Header().Get("DPoP-Nonce")
	_, err = station.NewPAR(t.Context(), c, par, chainProof(t, key, "POST", endpoint, nonce, ""))
	require.NoError(t, err)
	var session OAuthSession
	require.NoError(t, db.First(&session).Error)
	require.Equal(t, "atproto", session.DownstreamScope)
	par.Scope = testFullScope
	_, err = station.NewPAR(t.Context(), c, par, chainProof(t, key, "POST", endpoint, nonce, ""))
	require.Error(t, err, "the requested scope must still respect the station maximum")
}

func TestLegacyPublicHTTPSCallbackMetadata(t *testing.T) {
	o, _, _ := chainProxy(t)
	o.baseURL = ""
	o.public = true
	o.host = "station.example.com"
	o.clientMetadata.RedirectURIs = []string{"https://station.example.com/login"}
	meta, err := o.GetDownstreamMetadata(o.clientMetadata.RedirectURIs[0])
	require.NoError(t, err)
	resolved, err := o.downstreamMetadata(meta.ClientID, meta.RedirectURIs[0])
	require.NoError(t, err)
	require.Equal(t, meta.ClientID, resolved.ClientID)
	require.Equal(t, meta.RedirectURIs, resolved.RedirectURIs)
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestLocalPARRejectsUpstreamDPoP(t *testing.T) {
	o, db, key := chainProxy(t)
	meta, err := o.GetDownstreamMetadata(localOrigin + "/login")
	require.NoError(t, err)
	par := &PAR{ClientID: meta.ClientID, RedirectURI: meta.RedirectURIs[0], Scope: testFullScope,
		LoginHint: "did:plc:account", State: "frontend-state", CodeChallenge: "challenge", CodeChallengeMethod: "S256", ResponseType: "code"}
	c := o.Echo.NewContext(httptest.NewRequest(http.MethodPost, "/oauth/par", nil), httptest.NewRecorder())
	_, err = o.NewPAR(t.Context(), c, par, chainProof(t, key, "POST", "https://station.example.com/oauth/par", "", ""))
	require.Error(t, err)
	var count int64
	require.NoError(t, db.Model(&OAuthSession{}).Count(&count).Error)
	require.Zero(t, count, "wrong-boundary proof cannot persist a session")
	_, err = o.NewPAR(t.Context(), c, par, chainProof(t, key, "POST", localOrigin+"/oauth/par", "", ""))
	require.ErrorIs(t, err, ErrFirstNonce)
	nonce := c.Response().Header().Get("DPoP-Nonce")
	require.NotEmpty(t, nonce)
	resp, err := o.NewPAR(t.Context(), c, par, chainProof(t, key, "POST", localOrigin+"/oauth/par", nonce, ""))
	require.NoError(t, err)
	require.NotEmpty(t, resp.RequestURI)
	var session OAuthSession
	require.NoError(t, db.First(&session).Error)
	require.Equal(t, meta.ClientID, session.DownstreamClientID)
	require.Equal(t, "frontend-state", session.DownstreamState)
	require.Equal(t, testFullScope, session.DownstreamScope)
}

func TestLocalTokenRefreshResourceAndLogoutBoundaries(t *testing.T) {
	o, db, key := chainProxy(t)
	meta, err := o.GetDownstreamMetadata(localOrigin + "/login")
	require.NoError(t, err)
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	proof := chainProof(t, key, "POST", localOrigin+"/oauth/token", "", "")
	jkt, _, err := getJKT(proof)
	require.NoError(t, err)
	expiry := time.Now().Add(time.Hour)
	session := &OAuthSession{DID: "did:plc:account", PDSUrl: "https://station.example.com",
		UpstreamAccessToken: "station-access", UpstreamRefreshToken: "station-refresh", UpstreamAccessTokenExp: &expiry,
		UpstreamScope: "atproto", DownstreamScope: testFullScope,
		DownstreamDPoPJKT: jkt, DownstreamDPoPNoncePad: makeNoncePad(), DownstreamClientID: meta.ClientID,
		DownstreamRedirectURI: localOrigin + "/login", DownstreamAuthorizationCode: "one-use-code",
		DownstreamCodeChallenge: base64.RawURLEncoding.EncodeToString(hash[:])}
	require.NoError(t, db.Create(session).Error)
	request := &TokenRequest{GrantType: "authorization_code", ClientID: meta.ClientID, RedirectURI: session.DownstreamRedirectURI, Code: session.DownstreamAuthorizationCode, CodeVerifier: verifier}
	_, err = o.Token(t.Context(), request, chainProof(t, key, "POST", "https://station.example.com/oauth/token", "", ""), session)
	require.Error(t, err)
	require.Empty(t, session.DownstreamAccessToken, "proof is validated before code consumption")
	wrongClient := *request
	wrongClient.ClientID = "https://evil.example/client.json"
	_, err = o.Token(t.Context(), &wrongClient, proof, session)
	require.Error(t, err)
	tokens, err := o.Token(t.Context(), request, proof, session)
	require.NoError(t, err)
	require.Equal(t, "atproto", tokens.Scope, "a reduced upstream grant cannot become the configured full scope")
	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(tokens.AccessToken, claims)
	require.NoError(t, err)
	require.Equal(t, localOrigin, claims["iss"])
	require.Equal(t, meta.ClientID, claims["client_id"])
	_, err = o.Token(t.Context(), request, proof, session)
	require.Error(t, err, "authorization code is single use")
	refresh := &TokenRequest{GrantType: "refresh_token", ClientID: meta.ClientID, RefreshToken: tokens.RefreshToken}
	_, err = o.Token(t.Context(), refresh, chainProof(t, key, "POST", "https://station.example.com/oauth/token", "", ""), session)
	require.Error(t, err)
	renewed, err := o.Token(t.Context(), refresh, proof, session)
	require.NoError(t, err)
	require.Equal(t, "atproto", renewed.Scope)
	nonce := generateValidNonces(session.DownstreamDPoPNoncePad, time.Now())[0]
	resource := "/xrpc/com.atproto.repo.listRecords"
	serve := func(endpoint string) int {
		req := httptest.NewRequest(http.MethodGet, resource, nil)
		req.Header.Set("Authorization", "DPoP "+session.DownstreamAccessToken)
		req.Header.Set("DPoP", chainProof(t, key, "GET", endpoint, nonce, session.DownstreamAccessToken))
		rec := httptest.NewRecorder()
		c := o.Echo.NewContext(req, rec)
		err := o.OAuthMiddleware(func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })(c)
		if err != nil {
			o.Echo.HTTPErrorHandler(err, c)
		}
		return rec.Code
	}
	require.NotEqual(t, http.StatusNoContent, serve("https://station.example.com"+resource))
	require.Equal(t, http.StatusNoContent, serve(localOrigin+resource))
	logoutProof := chainProof(t, key, "POST", localOrigin+"/oauth/revoke", nonce, "")
	require.NoError(t, o.Revoke(t.Context(), logoutProof, &RevokeRequest{ClientID: meta.ClientID, Token: "unknown"}))
	loaded, err := o.userGetOAuthSession(jkt)
	require.NoError(t, err)
	require.Nil(t, loaded.DownstreamRevokedAt)
	require.NoError(t, o.Revoke(t.Context(), logoutProof, &RevokeRequest{ClientID: meta.ClientID, Token: tokens.RefreshToken}))
	loaded, err = o.userGetOAuthSession(jkt)
	require.NoError(t, err)
	require.Equal(t, OAuthSessionStateReadyUpstream, loaded.Status())
	require.Equal(t, "station-refresh", loaded.UpstreamRefreshToken, "logout retains the independent upstream session")
	require.NotEqual(t, http.StatusNoContent, serve(localOrigin+resource))
}

type chainTransport func(*http.Request) (*http.Response, error)

func (f chainTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDelegationUsesStationNotResolvedPDS(t *testing.T) {
	o, db, key := chainProxy(t)
	meta, err := o.GetDownstreamMetadata(localOrigin + "/login")
	require.NoError(t, err)
	requestURI := makeURN("delegation-jkt")
	session := &OAuthSession{DownstreamDPoPJKT: "delegation-jkt", DownstreamPARRequestURI: requestURI,
		DownstreamClientID: meta.ClientID, DownstreamRedirectURI: localOrigin + "/login", DownstreamScope: "atproto", Handle: "did:plc:account"}
	require.NoError(t, db.Create(session).Error)
	var parSeen bool
	o.httpClient = &http.Client{Transport: chainTransport(func(r *http.Request) (*http.Response, error) {
		var body string
		switch r.URL.Host + r.URL.Path {
		case "plc.directory/did:plc:account":
			body = `{"alsoKnownAs":["at://account.example.com"],"service":[{"id":"#atproto_pds","serviceEndpoint":"https://real-pds.example.com"}]}`
		case "station.example.com/.well-known/oauth-protected-resource":
			body = `{"resource":"https://station.example.com","authorization_servers":["https://station.example.com"]}`
		case "station.example.com/.well-known/oauth-authorization-server":
			bodyBytes, err := json.Marshal(generateOAuthServerMetadata("station.example.com"))
			require.NoError(t, err)
			body = string(bodyBytes)
		case "station.example.com/oauth/par":
			parSeen = true
			require.NoError(t, r.ParseForm())
			require.Equal(t, "", r.Form.Get("client_assertion"))
			require.Equal(t, localOrigin+"/oauth/return", r.Form.Get("redirect_uri"))
			require.Equal(t, "atproto", r.Form.Get("scope"))
			body = `{"request_uri":"urn:station-par","expires_in":30}`
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		default:
			return nil, fmt.Errorf("unexpected request to %s", r.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	redirect, httpErr := o.Authorize(context.Background(), requestURI, meta.ClientID)
	require.Nil(t, httpErr)
	require.True(t, parSeen)
	require.Equal(t, "station.example.com", mustParseURL(t, redirect).Host)
	loaded, err := o.userGetOAuthSession(session.DownstreamDPoPJKT)
	require.NoError(t, err)
	require.Equal(t, "https://station.example.com", loaded.PDSUrl)
	require.Equal(t, "did:plc:account", loaded.DID)
	upstreamKey, err := jwk.ParseKey([]byte(loaded.UpstreamDPoPPrivateJWK))
	require.NoError(t, err)
	localProof := chainProof(t, key, "GET", localOrigin+"/xrpc/test", "", "")
	upstreamProof := chainProof(t, upstreamKey, "GET", "https://station.example.com/xrpc/test", "", "")
	localJKT, _, err := getJKT(localProof)
	require.NoError(t, err)
	upstreamJKT, _, err := getJKT(upstreamProof)
	require.NoError(t, err)
	require.NotEqual(t, localJKT, upstreamJKT, "every proxy hop owns a distinct DPoP session")
	_, httpErr = o.Return(t.Context(), "code", "https://wrong-issuer.example", loaded.UpstreamState)
	require.NotNil(t, httpErr)
	_, httpErr = o.Return(t.Context(), "code", loaded.UpstreamAuthServerIssuer, makeState(loaded.DownstreamDPoPJKT))
	require.NotNil(t, httpErr)
}
