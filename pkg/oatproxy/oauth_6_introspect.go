package oatproxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// IntrospectionResponse is an RFC 7662 token introspection response.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

var inactiveToken = &IntrospectionResponse{Active: false}

// HandleOAuthIntrospect implements RFC 7662 self-introspection for
// downstream access tokens. It must be mounted behind OAuthMiddleware: the
// caller authenticates with its own DPoP-bound access token, and may only
// introspect that token. An optional `token` form parameter (per RFC 7662)
// is accepted, but anything other than the caller's own current token
// reports inactive rather than leaking information.
func (o *OATProxy) HandleOAuthIntrospect(c echo.Context) error {
	session, ok := c.Get("session").(*OAuthSession)
	if !ok || session == nil {
		return c.JSON(http.StatusOK, inactiveToken)
	}

	authHeader := c.Request().Header.Get("Authorization")
	presented := strings.TrimPrefix(authHeader, "DPoP ")
	if presented == "" {
		return c.JSON(http.StatusOK, inactiveToken)
	}
	token := c.FormValue("token")
	if token == "" {
		token = presented
	}
	if token != presented || token != session.DownstreamAccessToken {
		return c.JSON(http.StatusOK, inactiveToken)
	}
	if session.Status() != OAuthSessionStateReady {
		return c.JSON(http.StatusOK, inactiveToken)
	}

	// OAuthMiddleware already verified the token's signature and DPoP
	// binding, so an unverified parse is safe here.
	claims := jwt.RegisteredClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		return c.JSON(http.StatusOK, inactiveToken)
	}

	downstreamMeta, err := o.GetDownstreamMetadata("")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to get downstream metadata: %s", err))
	}

	resp := &IntrospectionResponse{
		Active:    true,
		Scope:     o.grantedScope(session),
		ClientID:  downstreamMeta.ClientID,
		TokenType: "DPoP",
		Sub:       session.DID,
		Aud:       fmt.Sprintf("did:web:%s", o.host),
		Iss:       fmt.Sprintf("https://%s", o.host),
		Jti:       claims.ID,
	}
	if claims.ExpiresAt != nil {
		resp.Exp = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		resp.Iat = claims.IssuedAt.Unix()
	}
	return c.JSON(http.StatusOK, resp)
}
