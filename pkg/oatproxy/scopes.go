package oatproxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// ParseScope splits a space-separated OAuth scope string into its
// individual scope values.
func ParseScope(scope string) []string {
	return strings.Fields(scope)
}

// ScopeContains reports whether the space-separated scope string `granted`
// includes every scope value of `wanted`. Scope values are compared as
// exact strings; no attempt is made to reason about one scope implying
// another (e.g. transition:generic vs. granular repo:* grants).
func ScopeContains(granted, wanted string) bool {
	grantedSet := map[string]bool{}
	for _, s := range ParseScope(granted) {
		grantedSet[s] = true
	}
	for _, s := range ParseScope(wanted) {
		if !grantedSet[s] {
			return false
		}
	}
	return true
}

// GrantedScope returns the scope that was granted to this session. Sessions
// created before OATProxy tracked per-session scopes have no scope recorded;
// those sessions were granted the full scope the proxy was configured with
// at the time, so callers should treat an empty return value as "everything
// the application asks for". HasScope implements exactly that rule.
func (s *OAuthSession) GrantedScope() string {
	if s.UpstreamScope != "" {
		return s.UpstreamScope
	}
	return s.DownstreamScope
}

// HasScope reports whether this session was granted every scope value in
// `wanted` (space-separated). Legacy sessions with no recorded scope are
// treated as having the full configured scope, i.e. HasScope returns true.
func (s *OAuthSession) HasScope(wanted string) bool {
	granted := s.GrantedScope()
	if granted == "" {
		return true
	}
	return ScopeContains(granted, wanted)
}

// grantedScope is GrantedScope with the legacy empty case resolved to the
// configured scope, for surfaces (tokens, JWTs, introspection) that must
// report a concrete scope string.
func (o *OATProxy) grantedScope(session *OAuthSession) string {
	if scope := session.GrantedScope(); scope != "" {
		return scope
	}
	return o.scope
}

// validateRequestedScope checks a downstream PAR scope request against the
// configured scope: it must be a non-empty subset that includes "atproto".
func (o *OATProxy) validateRequestedScope(requested string) *echo.HTTPError {
	if !ScopeContains(requested, "atproto") {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid scope: the atproto scope is required")
	}
	if !ScopeContains(o.scope, requested) {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid scope: must be a subset of %s, got %s", o.scope, requested))
	}
	return nil
}
