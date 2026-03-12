package oatproxy

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/xrpc"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	oauth "github.com/streamplace/atproto-oauth-golang"
)

var xrpcClient *oauth.XrpcClient

type XrpcClient struct {
	client           *oauth.XrpcClient
	authArgs         *oauth.XrpcAuthedRequestArgs
	rateLimitedUntil time.Time
	o                *OATProxy
}

func (o *OATProxy) GetXrpcClient(session *OAuthSession) (*XrpcClient, error) {
	key, err := jwk.ParseKey([]byte(session.UpstreamDPoPPrivateJWK))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DPoP private JWK: %w", err)
	}
	o.clientMutex.Lock()
	defer o.clientMutex.Unlock()
	client, ok := o.clients[session.DID]
	if ok {
		return client, nil
	}
	authArgs := &oauth.XrpcAuthedRequestArgs{
		Did:            session.DID,
		AccessToken:    session.UpstreamAccessToken,
		PdsUrl:         session.PDSUrl,
		Issuer:         session.UpstreamAuthServerIssuer,
		DpopPdsNonce:   session.UpstreamDPoPNonce,
		DpopPrivateJwk: key,
	}

	xrpcClient := &oauth.XrpcClient{
		OnDpopPdsNonceChanged: func(did, newNonce string) {
			sess, err := o.getOAuthSession(session.DownstreamDPoPJKT)
			if err != nil {
				o.slog.Error("failed to get OAuth session in OnDpopPdsNonceChanged", "error", err)
				return
			}
			sess.UpstreamDPoPNonce = newNonce
			err = o.updateOAuthSession(session.DownstreamDPoPJKT, sess)
			if err != nil {
				o.slog.Error("failed to update OAuth session in OnDpopPdsNonceChanged", "error", err)
			}
			o.slog.Info("updated OAuth session in OnDpopPdsNonceChanged", "session", sess)
		},
	}
	o.clients[session.DID] = &XrpcClient{client: xrpcClient, authArgs: authArgs}
	return &XrpcClient{client: xrpcClient, authArgs: authArgs, o: o}, nil
}

func (c *XrpcClient) Do(ctx context.Context, kind string, inpenc, method string, params map[string]any, bodyobj any, out any) error {
	if c.rateLimitedUntil.After(time.Now()) {
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("request not attempted, rate-limited by upstream (will reset at %s)", c.rateLimitedUntil.Format(time.RFC3339)))
	}
	err := c.client.Do(ctx, c.authArgs, kind, inpenc, method, params, bodyobj, out)
	if err == nil {
		return nil
	}
	xErr, ok := err.(*xrpc.Error)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if xErr.StatusCode == http.StatusTooManyRequests {
		if xErr.Ratelimit == nil {
			c.o.slog.Warn("rate-limited by upstream, but ratelimit header not found")
			return echo.NewHTTPError(http.StatusTooManyRequests, "rate-limited by upstream, but ratelimit header not found")
		}
		c.rateLimitedUntil = xErr.Ratelimit.Reset
		return echo.NewHTTPError(http.StatusTooManyRequests, fmt.Sprintf("http 429 from upstream (will reset at %s)", c.rateLimitedUntil.Format(time.RFC3339)))
	}
	return xErr
}

func (c *XrpcClient) SetHeaders(headers map[string]string) {
	c.client.Headers = headers
}
