package oatproxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/xrpc"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
)

func (o *OATProxy) HandleWildcard(c echo.Context) error {
	ctx, span := otel.Tracer("server").Start(c.Request().Context(), "HandleWildcard")
	defer span.End()

	session, client := GetOAuthSession(ctx)
	if session == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "oauth session not found")
	}

	forwarded := map[string]string{}
	for _, name := range []string{"atproto-proxy", "atproto-accept-labelers"} {
		if v := c.Request().Header.Get(name); v != "" {
			forwarded[name] = v
		}
	}
	if len(forwarded) > 0 {
		client.SetHeaders(forwarded)
	}

	var out map[string]any

	// Get the last path segment in the URL
	path := c.Request().URL.Path
	segments := strings.Split(path, "/")
	lastSegment := segments[len(segments)-1]

	var xrpcType string
	var err error
	if c.Request().Method == "GET" {
		xrpcType = xrpc.Query
		queryParams := make(map[string]any)
		for k, v := range c.QueryParams() {
			for _, vv := range v {
				queryParams[k] = vv
			}
		}
		err = client.Do(ctx, xrpcType, "application/json", lastSegment, queryParams, nil, &out)
	} else {
		xrpcType = xrpc.Procedure
		var body map[string]any
		if err := c.Bind(&body); err != nil {
			return c.JSON(http.StatusBadRequest, xrpc.XRPCError{ErrStr: "BadRequest", Message: fmt.Sprintf("invalid body: %s", err)})
		}
		err = client.Do(ctx, xrpcType, "application/json", lastSegment, nil, body, &out)
	}

	if err != nil {
		if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "EOF") {
			return c.JSON(200, map[string]any{})
		}
		o.slog.Error("upstream xrpc error", "error", err)
		return err
	}

	return c.JSON(200, out)
}
