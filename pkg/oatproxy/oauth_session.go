package oatproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

var refreshWhenRemaining = time.Minute * 15

// OAuthSession stores authentication data needed during the OAuth flow
type OAuthSession struct {
	DID    string `json:"did" gorm:"column:repo_did;index"`
	Handle string `json:"handle" gorm:"column:handle;index"` // possibly also did if they have no handle
	PDSUrl string `json:"pds_url" gorm:"column:pds_url;index"`

	// Upstream fields
	UpstreamState            string     `json:"upstream_state" gorm:"column:upstream_state;index"`
	UpstreamAuthServerIssuer string     `json:"upstream_auth_server_issuer" gorm:"column:upstream_auth_server_issuer"`
	UpstreamPKCEVerifier     string     `json:"upstream_pkce_verifier" gorm:"column:upstream_pkce_verifier"`
	UpstreamDPoPNonce        string     `json:"upstream_dpop_nonce" gorm:"column:upstream_dpop_nonce"`
	UpstreamDPoPPrivateJWK   string     `json:"upstream_dpop_private_jwk" gorm:"column:upstream_dpop_private_jwk;type:text"`
	UpstreamAccessToken      string     `json:"upstream_access_token" gorm:"column:upstream_access_token"`
	UpstreamAccessTokenExp   *time.Time `json:"upstream_access_token_exp" gorm:"column:upstream_access_token_exp"`
	UpstreamRefreshToken     string     `json:"upstream_refresh_token" gorm:"column:upstream_refresh_token"`
	UpstreamAuthServerURL    string     `json:"upstream_auth_server_url" gorm:"column:upstream_auth_server_url"`
	UpstreamScope            string     `json:"upstream_scope" gorm:"column:upstream_scope"`
	// This field should be named UpstreamRevokedAt but it keeps its name for backwards compatibility
	RevokedAt *time.Time `json:"revoked_at" gorm:"column:revoked_at"`

	// Downstream fields
	DownstreamDPoPNoncePad      string     `json:"downstream_dpop_nonce_pad" gorm:"column:downstream_dpop_nonce_pad"`
	DownstreamDPoPJKT           string     `json:"downstream_dpop_jkt" gorm:"column:downstream_dpop_jkt;primaryKey"`
	DownstreamAccessToken       string     `json:"downstream_access_token" gorm:"column:downstream_access_token;index"`
	DownstreamRefreshToken      string     `json:"downstream_refresh_token" gorm:"column:downstream_refresh_token;index"`
	DownstreamAuthorizationCode string     `json:"downstream_authorization_code" gorm:"column:downstream_authorization_code;index"`
	DownstreamState             string     `json:"downstream_state" gorm:"column:downstream_state"`
	DownstreamScope             string     `json:"downstream_scope" gorm:"column:downstream_scope"`
	DownstreamCodeChallenge     string     `json:"downstream_code_challenge" gorm:"column:downstream_code_challenge"`
	DownstreamPARRequestURI     string     `json:"downstream_par_request_uri" gorm:"column:downstream_par_request_uri"`
	DownstreamPARUsedAt         *time.Time `json:"downstream_par_used_at" gorm:"column:downstream_par_used_at"`
	DownstreamRedirectURI       string     `json:"downstream_redirect_uri" gorm:"column:downstream_redirect_uri"`
	DownstreamJTICache          string     `json:"downstream_jti_cache" gorm:"column:downstream_jti_cache"`
	// Indicates that the session has been revoked by the downstream user, but upstream still might be valid
	DownstreamRevokedAt *time.Time `json:"downstream_revoked_at" gorm:"column:downstream_revoked_at"`

	// Deprecated and unused
	XXDONTUSEDownstreamDPoPNonce string `json:"downstream_dpop_nonce" gorm:"column:downstream_dpop_nonce"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// for gorm. this is prettier than "o_auth_sessions"
func (o *OAuthSession) TableName() string {
	return "oauth_sessions"
}

type OAuthSessionStatus string

const (
	// We've gotten the first request and sent it back for a new nonce
	OAuthSessionStatePARPending OAuthSessionStatus = "par-pending"
	// PAR has been created, but not yet used
	OAuthSessionStatePARCreated OAuthSessionStatus = "par-created"
	// PAR has been used, but maybe upstream will fail for some reason
	OAuthSessionStatePARUsed OAuthSessionStatus = "par-used"
	// PAR has been used, we're waiting to hear back from upstream
	OAuthSessionStateUpstream OAuthSessionStatus = "upstream"
	// Upstream came back, we've issued the user a code but it hasn't been used yet
	OAuthSessionStateDownstream OAuthSessionStatus = "downstream"
	// Code has been used, everything is good
	OAuthSessionStateReady OAuthSessionStatus = "ready"
	// Downstream is rejected, the user logged out. Upstream is still okay as far as we know.
	OAuthSessionStateReadyUpstream OAuthSessionStatus = "ready-upstream"
	// For any reason we're done. Revoked or expired
	OAuthSessionStateRejected OAuthSessionStatus = "rejected"
)

func (o *OAuthSession) Status() OAuthSessionStatus {
	if o.RevokedAt != nil {
		return OAuthSessionStateRejected
	}
	if o.DownstreamRevokedAt != nil {
		return OAuthSessionStateReadyUpstream
	}
	if o.DownstreamAccessToken != "" {
		return OAuthSessionStateReady
	}
	if o.DownstreamAuthorizationCode != "" {
		return OAuthSessionStateDownstream
	}
	if o.UpstreamDPoPPrivateJWK != "" {
		return OAuthSessionStateUpstream
	}
	if o.DownstreamPARUsedAt != nil {
		return OAuthSessionStatePARUsed
	}
	if o.DownstreamPARRequestURI != "" {
		return OAuthSessionStatePARCreated
	}
	bs, _ := json.Marshal(o)
	fmt.Printf("unknown oauth session status: %s\n", string(bs))
	// todo: this should never happen, log a warning? panic?
	return OAuthSessionStateRejected
}

type JTICacheEntry struct {
	JTI  string    `json:"jti"`
	Time time.Time `json:"time"`
}

// adds a new JTI to session.DownstreamJTICache. does not save, that's up to the caller.
func (o *OAuthSession) CacheJTI(jti string) error {
	if o.DownstreamJTICache == "" {
		o.DownstreamJTICache = "[]"
	}

	entries := []JTICacheEntry{}
	err := json.Unmarshal([]byte(o.DownstreamJTICache), &entries)
	if err != nil {
		return fmt.Errorf("failed to unmarshal downstream jti cache: %w", err)
	}
	maxTime := EpochLength * ValidEpochs

	outEntries := []JTICacheEntry{}
	for _, entry := range entries {
		if entry.JTI == jti {
			return fmt.Errorf("jti already used")
		}
		if time.Since(entry.Time) > time.Duration(maxTime) {
			continue
		}
		outEntries = append(outEntries, entry)
	}

	outEntries = append(outEntries, JTICacheEntry{
		JTI:  jti,
		Time: time.Now(),
	})

	bs, err := json.Marshal(outEntries)
	if err != nil {
		return fmt.Errorf("failed to marshal downstream jti cache: %w", err)
	}
	o.DownstreamJTICache = string(bs)
	return nil
}

func (o *OATProxy) RefreshIfNeeded(session *OAuthSession) (*OAuthSession, error) {
	return o.getOAuthSession(session.DownstreamDPoPJKT)
}

func (o *OATProxy) getOAuthSession(jkt string) (*OAuthSession, error) {
	session, err := o.userGetOAuthSession(jkt)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, nil
	}
	if session.Status() != OAuthSessionStateReady {
		return session, nil
	}

	timeUntilExpiry := time.Until(*session.UpstreamAccessTokenExp)
	// Add some randomization to prevent multiple nodes from refreshing at the same time
	jitter := time.Duration(rand.Int63n(int64(refreshWhenRemaining / 4)))
	if timeUntilExpiry > refreshWhenRemaining+jitter {
		return session, nil
	}

	// nobody do anything until refresh
	unlock, err := o.lock(jkt)
	if err != nil {
		return nil, fmt.Errorf("failed to lock session: %w", err)
	}
	defer unlock()

	oldSession := session
	// need to reload in case somebody else just refreshed
	session, err = o.userGetOAuthSession(jkt)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, nil
	}
	if !oldSession.UpstreamAccessTokenExp.Equal(*session.UpstreamAccessTokenExp) {
		// someone else refreshed, that's chill
		return session, nil
	}
	if session.Status() != OAuthSessionStateReady && session.Status() != OAuthSessionStateReadyUpstream {
		return session, nil
	}

	// migration! we didn't always have this field.
	if session.DownstreamDPoPNoncePad == "" {
		session.DownstreamDPoPNoncePad = makeNoncePad()
		err = o.updateOAuthSession(session.DownstreamDPoPJKT, session)
		if err != nil {
			return nil, fmt.Errorf("could not update downstream session: %w", err)
		}
	}

	oclient, err := o.GetOauthClient()

	dpopKey, err := jwk.ParseKey([]byte(session.UpstreamDPoPPrivateJWK))
	if err != nil {
		return nil, fmt.Errorf("failed to parse upstream dpop private key: %w", err)
	}

	// refresh upstream before returning
	resp, refreshErr := oclient.RefreshTokenRequest(context.Background(), session.UpstreamRefreshToken, session.UpstreamAuthServerIssuer, session.UpstreamDPoPNonce, dpopKey)
	if refreshErr != nil {
		// revoke, probably
		o.slog.Error("failed to refresh upstream token, revoking session", "error", refreshErr)
		now := time.Now()
		session.RevokedAt = &now
		// technically RevokedAt implies DownstreamRevokedAt but we'll be explicit here
		if session.DownstreamRevokedAt == nil {
			session.DownstreamRevokedAt = &now
		}
		err = o.updateOAuthSession(session.DownstreamDPoPJKT, session)
		if err != nil {
			o.slog.Error("after upstream token refresh, failed to revoke session", "error", err)
		}
		return nil, fmt.Errorf("failed to refresh upstream token: %w", refreshErr)
	}

	exp := time.Now().Add(time.Second * time.Duration(resp.ExpiresIn)).UTC()
	session.UpstreamAccessToken = resp.AccessToken
	session.UpstreamAccessTokenExp = &exp
	session.UpstreamRefreshToken = resp.RefreshToken

	err = o.updateOAuthSession(session.DownstreamDPoPJKT, session)
	if err != nil {
		return nil, fmt.Errorf("failed to update downstream session after upstream token refresh: %w", err)
	}

	o.slog.Info("refreshed upstream token", "session", session.DownstreamDPoPJKT, "did", session.DID)

	return session, nil
}
