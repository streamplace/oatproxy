package oatproxy

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// AuthorizationResponse is what a downstream client's authorization redirect would carry.
type AuthorizationResponse struct {
	Code  string
	State string
	Iss   string
}

// errPARNotPending marks a request URI that names no pending pushed authorization request.
var errPARNotPending = errors.New("pushed authorization request is not pending")

// pendingPAR loads the session owning requestURI (whose key is jkt) and checks
// the request is still awaiting approval.
func (o *OATProxy) pendingPAR(jkt, requestURI string) (*OAuthSession, error) {
	session, err := o.userGetOAuthSession(jkt)
	if err != nil {
		return nil, fmt.Errorf("failed to load session: %w", err)
	}
	if session == nil || session.DownstreamPARRequestURI != requestURI {
		return nil, fmt.Errorf("pushed authorization request not found: %w", errPARNotPending)
	}
	if status := session.Status(); status != OAuthSessionStatePARCreated {
		return nil, fmt.Errorf("pushed authorization request is %s: %w", status, errPARNotPending)
	}
	return session, nil
}

// CheckPendingPAR reports whether requestURI names a pushed authorization
// request that has not been approved, linked or sent upstream yet. A false
// result with a nil error means the request is malformed, unknown or spent;
// a non-nil error means it could not be checked.
func (o *OATProxy) CheckPendingPAR(ctx context.Context, requestURI string) (bool, error) {
	jkt, _, err := parseURN(requestURI)
	if err != nil {
		return false, nil
	}
	if _, err := o.pendingPAR(jkt, requestURI); err != nil {
		if errors.Is(err, errPARNotPending) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// LinkSession completes the pushed authorization request requestURI without
// sending its user upstream: the new downstream session shares approver's
// upstream session (following approver's own link, if any). Its scope is
// capped by both approver's grant and the root's. Upstream refresh
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
	session, err := o.pendingPAR(jkt, requestURI)
	if err != nil {
		return nil, err
	}

	code, err := generateAuthorizationCode()
	if err != nil {
		return nil, fmt.Errorf("could not generate authorization code: %w", err)
	}
	requested := session.DownstreamScope
	if requested == "" {
		requested = o.scope
	}
	granted := intersectScope(intersectScope(requested, o.grantedScope(approver)), o.grantedScope(root))
	if !ScopeContains(granted, "atproto") {
		return nil, fmt.Errorf("approver cannot grant the requested scope")
	}
	now := time.Now()
	session.UpstreamJKT = rootJKT
	session.DID = root.DID
	session.Handle = root.Handle
	session.PDSUrl = root.PDSUrl
	session.DownstreamScope = granted
	session.DownstreamPARUsedAt = &now
	session.DownstreamAuthorizationCode = code
	err = o.saveSession(session)
	if err != nil {
		return nil, fmt.Errorf("could not update session: %w", err)
	}

	return &AuthorizationResponse{
		Code:  code,
		State: session.DownstreamState,
		Iss:   o.origin(),
	}, nil
}
