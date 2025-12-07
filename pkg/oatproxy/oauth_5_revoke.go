package oatproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/AxisCommunications/go-dpop"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
)

func (o *OATProxy) HandleOAuthRevoke(c echo.Context) error {
	ctx, span := otel.Tracer("server").Start(c.Request().Context(), "HandleOAuthRevoke")
	defer span.End()
	var revokeRequest RevokeRequest
	if err := c.Bind(&revokeRequest); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid request: %s", err))
	}
	dpopHeader := c.Request().Header.Get("DPoP")
	if dpopHeader == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "DPoP header is required")
	}
	err := o.Revoke(ctx, dpopHeader, &revokeRequest)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("could not handle oauth revoke: %s", err))
	}
	return c.JSON(http.StatusOK, map[string]interface{}{})
}

func (o *OATProxy) Revoke(ctx context.Context, dpopHeader string, revokeRequest *RevokeRequest) error {
	jkt, _, err := getJKT(dpopHeader)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to get JKT from DPoP header header=%s: %s", dpopHeader, err))
	}
	session, err := o.getOAuthSession(jkt)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("could not get oauth session: %s", err))
	}
	_, httpErr := dpop.Parse(dpopHeader, dpop.POST, o.authServerURL(session, "/oauth/revoke"), dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &dpopTimeWindow,
	})
	if httpErr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid DPoP proof")
	}

	now := time.Now()
	slog.Info("revoking session by user request", "session", session.DownstreamDPoPJKT, "did", session.DID)
	session.DownstreamRevokedAt = &now
	err = o.updateOAuthSession(session.DownstreamDPoPJKT, session)
	if err != nil {
		return fmt.Errorf("could not update downstream session: %w", err)
	}

	return nil
}
