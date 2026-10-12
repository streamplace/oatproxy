package oatproxy

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
)

func validateOrigin(raw string, allowLoopback bool) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid OAuth origin %q", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if allowLoopback && u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("OAuth origin must use HTTPS (or explicit numeric HTTP loopback): %q", raw)
}

func (o *OATProxy) origin() string {
	if o.baseURL != "" {
		return strings.TrimSuffix(o.baseURL, "/")
	}
	return "https://" + o.host
}

func (o *OATProxy) endpoint(path string) *url.URL {
	u, _ := url.Parse(o.origin() + path)
	return u
}

func (o *OATProxy) loopback() bool {
	return strings.HasPrefix(o.origin(), "http://")
}

func validLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback() && u.Port() != ""
}

// localhost client IDs are self-describing public clients under the AT Protocol
// OAuth profile. They never authorize a network metadata fetch or client assertion.
func (o *OATProxy) downstreamMetadata(clientID, redirectURI string) (*OAuthClientMetadata, error) {
	u, err := url.Parse(clientID)
	if err == nil && u.Scheme == "http" && u.Host == "localhost" && u.User == nil && u.Path == "" && u.Fragment == "" {
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil || len(q) != 2 || len(q["scope"]) != 1 || len(q["redirect_uri"]) != 1 || o.validateRequestedScope(q.Get("scope")) != nil || q.Get("redirect_uri") != redirectURI || !validLoopbackRedirect(redirectURI) {
			return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid localhost client metadata")
		}
		if o.loopback() {
			redirect, _ := url.Parse(redirectURI)
			if redirect.Scheme+"://"+redirect.Host != o.origin() ||
				(redirect.Path != "/login" && redirect.Path != "/api/app-return" && redirect.Path != "/oauth/return" && !strings.HasPrefix(redirect.Path, "/app-return/")) {
				return nil, echo.NewHTTPError(http.StatusBadRequest, "redirect_uri does not belong to this local node")
			}
		}
		meta := *o.clientMetadata
		meta.ClientID = clientID
		meta.ClientURI = "http://localhost"
		meta.RedirectURIs = []string{redirectURI}
		meta.Scope = q.Get("scope")
		meta.TokenEndpointAuthMethod = "none"
		meta.ResponseTypes = []string{"code"}
		meta.GrantTypes = []string{"authorization_code", "refresh_token"}
		meta.DPoPBoundAccessTokens = boolPtr(true)
		return &meta, nil
	}
	return o.GetDownstreamMetadata(redirectURI)
}

func (o *OATProxy) sessionMetadata(session *OAuthSession) (*OAuthClientMetadata, error) {
	if session.DownstreamClientID != "" {
		return o.downstreamMetadata(session.DownstreamClientID, session.DownstreamRedirectURI)
	}
	return o.GetDownstreamMetadata(session.DownstreamRedirectURI)
}
