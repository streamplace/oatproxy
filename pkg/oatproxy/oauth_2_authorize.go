package oatproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	oauth "github.com/streamplace/atproto-oauth-golang"
	"github.com/streamplace/atproto-oauth-golang/helpers"
	"go.opentelemetry.io/otel"
)

func (o *OATProxy) HandleOAuthAuthorize(c echo.Context) error {
	ctx, span := otel.Tracer("server").Start(c.Request().Context(), "HandleOAuthAuthorize")
	defer span.End()
	c.Response().Header().Set("Access-Control-Allow-Origin", "*")
	requestURI := c.QueryParam("request_uri")
	if requestURI == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "request_uri is required")
	}
	clientID := c.QueryParam("client_id")
	if clientID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "client_id is required")
	}
	redirectURL, redirectErr := o.Authorize(ctx, requestURI, clientID)
	if redirectErr != nil {
		// we're a redirect; if we fail we need to send the user back
		jkt, _, err := parseURN(requestURI)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to parse URN: %s", err))
		}

		session, err := o.getOAuthSession(jkt)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to load OAuth session jkt=%s: %s", jkt, err))
		}

		if session == nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("no session found for jkt=%s", jkt))
		}

		u, err := url.Parse(session.DownstreamRedirectURI)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to parse downstream redirect URI: %s", err))
		}
		q := u.Query()
		q.Set("error", "authorize_failed")
		q.Set("error_description", redirectErr.Error())
		u.RawQuery = q.Encode()
		return c.Redirect(http.StatusTemporaryRedirect, u.String())
	}
	return c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// downstream --> upstream transition; attempt to send user to the upstream auth server
func (o *OATProxy) Authorize(ctx context.Context, requestURI, clientID string) (string, *echo.HTTPError) {
	jkt, _, err := parseURN(requestURI)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to parse URN: %s", err))
	}

	session, err := o.getOAuthSession(jkt)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to load OAuth session jkt=%s: %s", jkt, err))
	}

	downstreamMeta, err := o.GetDownstreamMetadata(session.DownstreamRedirectURI)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to get downstream metadata: %s", err))
	}
	if !compareURLs(downstreamMeta.ClientID, clientID) {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("client ID mismatch: %s != %s", downstreamMeta.ClientID, clientID))
	}

	if session == nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("no session found for jkt=%s", jkt))
	}

	if session.Status() != OAuthSessionStatePARCreated {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("session is not in par-created state: %s", session.Status()))
	}

	if session.DownstreamPARRequestURI != requestURI {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("request URI mismatch: %s != %s", session.DownstreamPARRequestURI, requestURI))
	}

	now := time.Now()
	session.DownstreamPARUsedAt = &now
	err = o.updateOAuthSession(jkt, session)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to update OAuth session: %s", err))
	}

	upstreamMeta := o.GetUpstreamMetadata()
	oclient, err := o.GetOauthClient()
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to create OAuth client: %s", err))
	}

	var service string
	var did string
	if session.Handle != "" {

		if strings.HasPrefix(session.Handle, "http://") || strings.HasPrefix(session.Handle, "https://") {
			// we'll properly populate this after signup completes
			service = session.Handle
		} else {
			var httpErr *echo.HTTPError
			did, service, httpErr = ResolveHandleAndServiceWithClient(ctx, session.Handle, o.httpClient)
			if httpErr != nil {
				return "", httpErr
			}
			did, err = ResolveHandleWithClient(ctx, session.Handle, o.httpClient)
			if err != nil {
				return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to resolve handle '%s': %s", session.Handle, err))
			}

			var handle2 string
			service, handle2, err = ResolveServiceWithClient(ctx, did, o.httpClient)
			if err != nil {
				return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to resolve service for DID '%s': %s", did, err))
			}
			if handle2 != session.Handle {
				return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("handle mismatch: %s != %s", handle2, session.Handle))
			}
		}
	} else {
		service = o.defaultPDS
	}
	authserver, err := oclient.ResolvePdsAuthServer(ctx, service)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to resolve PDS auth server for service '%s': %s", service, err))
	}

	authmeta, err := oclient.FetchAuthServerMetadata(ctx, authserver)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to fetch auth server metadata from '%s': %s", authserver, err))
	}

	k, err := helpers.GenerateKey(nil)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to generate DPoP key: %s", err))
	}

	state := makeState(jkt)

	opts := oauth.ParAuthRequestOpts{
		State: state,
	}

	loginHint := session.Handle
	if strings.HasPrefix(session.Handle, "http://") || strings.HasPrefix(session.Handle, "https://") {
		loginHint = ""
	}

	parResp, err := oclient.SendParAuthRequest(ctx, authserver, authmeta, loginHint, upstreamMeta.Scope, k, opts)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to send PAR auth request to '%s': %s", authserver, err))
	}

	jwkJSON, err := json.Marshal(k)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to marshal DPoP key to JSON: %s", err))
	}

	u, err := url.Parse(authmeta.AuthorizationEndpoint)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to parse auth server metadata: %s", err))
	}
	u.RawQuery = fmt.Sprintf("client_id=%s&request_uri=%s", url.QueryEscape(upstreamMeta.ClientID), parResp.RequestUri)
	str := u.String()

	session.DID = did
	session.PDSUrl = service
	session.UpstreamState = parResp.State
	session.UpstreamAuthServerIssuer = authserver
	session.UpstreamPKCEVerifier = parResp.PkceVerifier
	session.UpstreamDPoPNonce = parResp.DpopAuthserverNonce
	session.UpstreamDPoPPrivateJWK = string(jwkJSON)

	err = o.updateOAuthSession(jkt, session)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to update OAuth session: %s", err))
	}

	return str, nil
}
