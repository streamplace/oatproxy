package oatproxy

import (
	"context"
	"fmt"
	"time"
)

// AuthorizationResponse is what a downstream client's authorization redirect would carry.
type AuthorizationResponse struct {
	Code  string
	State string
	Iss   string
}

// LinkSession completes the pushed authorization request requestURI without
// sending its user upstream: the new downstream session shares approver's
// upstream session (following approver's own link, if any). Upstream refresh
// tokens are single-use, so the linked session never holds a copy of them;
// it borrows the root's upstream state every time it's loaded. The client
// redeems the returned code at the token endpoint as after a normal login.
func (o *OATProxy) LinkSession(ctx context.Context, requestURI string, approver *OAuthSession) (*AuthorizationResponse, error) {
	if o.public {
		return nil, fmt.Errorf("session linking is not supported in public mode")
	}
	jkt, _, err := parseURN(requestURI)
	if err != nil {
		return nil, err
	}

	rootJKT := approver.DownstreamDPoPJKT
	if approver.UpstreamJKT != "" {
		rootJKT = approver.UpstreamJKT
	}
	if rootJKT == jkt {
		return nil, fmt.Errorf("cannot link a session to itself")
	}
	root, err := o.getOAuthSession(rootJKT)
	if err != nil {
		return nil, fmt.Errorf("failed to load approver session: %w", err)
	}
	if root == nil || root.UpstreamJKT != "" {
		return nil, fmt.Errorf("approver session not found")
	}
	if status := root.Status(); status != OAuthSessionStateReady && status != OAuthSessionStateReadyUpstream {
		return nil, fmt.Errorf("approver session is not ready: %s", status)
	}

	unlock, err := o.lock(jkt)
	if err != nil {
		return nil, fmt.Errorf("failed to lock session: %w", err)
	}
	defer unlock()
	session, err := o.userGetOAuthSession(jkt)
	if err != nil {
		return nil, fmt.Errorf("failed to load session: %w", err)
	}
	if session == nil || session.DownstreamPARRequestURI != requestURI {
		return nil, fmt.Errorf("pushed authorization request not found")
	}
	if status := session.Status(); status != OAuthSessionStatePARCreated {
		return nil, fmt.Errorf("pushed authorization request is not pending: %s", status)
	}

	code, err := generateAuthorizationCode()
	if err != nil {
		return nil, fmt.Errorf("could not generate authorization code: %w", err)
	}
	requested := session.DownstreamScope
	if requested == "" {
		requested = o.scope
	}
	now := time.Now()
	session.UpstreamJKT = rootJKT
	session.DID = root.DID
	session.Handle = root.Handle
	session.PDSUrl = root.PDSUrl
	session.DownstreamScope = intersectScope(requested, o.grantedScope(root))
	session.DownstreamPARUsedAt = &now
	session.DownstreamAuthorizationCode = code
	err = o.saveSession(session)
	if err != nil {
		return nil, fmt.Errorf("could not update session: %w", err)
	}

	return &AuthorizationResponse{
		Code:  code,
		State: session.DownstreamState,
		Iss:   fmt.Sprintf("https://%s", o.host),
	}, nil
}
