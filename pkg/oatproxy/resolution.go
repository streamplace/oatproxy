package oatproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	comatprototypes "github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel"
)

// func ResolveHandle(ctx context.Context, handle string) (string, error) {
// 	return ResolveHandleWithClient(ctx, handle, http.DefaultClient)
// }

// mostly borrowed from github.com/streamplace/atproto-oauth-golang, MIT license
func ResolveHandleWithClient(ctx context.Context, handle string, client *http.Client) (string, error) {
	var did string

	_, err := syntax.ParseHandle(handle)
	if err != nil {
		return "", err
	}

	recs, err := net.LookupTXT(fmt.Sprintf("_atproto.%s", handle))
	if err == nil {
		for _, rec := range recs {
			if strings.HasPrefix(rec, "did=") {
				did = strings.Split(rec, "did=")[1]
				break
			}
		}
	}

	if did == "" {
		req, err := http.NewRequestWithContext(
			ctx,
			"GET",
			fmt.Sprintf("https://%s/.well-known/atproto-did", handle),
			// "https://webhook.site/ce546544-f7ef-4880-9cbe-c2bf15ad9840",
			nil,
		)
		req.Header.Del("accept-encoding")
		if err != nil {
			return "", fmt.Errorf("unable to resolve handle: failed to create request: %s", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			return "", fmt.Errorf("unable to resolve handle, got http status %d", resp.StatusCode)
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("unable to resolve handle: failed to read response body: %s", err)
		}

		maybeDid := strings.TrimSpace(string(b))

		if _, err := syntax.ParseDID(maybeDid); err != nil {
			return "", fmt.Errorf("unable to resolve handle: failed to parse DID: %s", err)
		}

		did = maybeDid
	}

	return did, nil
}

// func ResolveService(ctx context.Context, did string) (string, string, error) {
// 	return ResolveServiceWithClient(ctx, did, http.DefaultClient)
// }

func ResolveServiceWithClient(ctx context.Context, did string, client *http.Client) (string, string, error) {
	type Identity struct {
		AlsoKnownAs []string `json:"alsoKnownAs"`
		Service     []struct {
			ID              string `json:"id"`
			Type            string `json:"type"`
			ServiceEndpoint string `json:"serviceEndpoint"`
		} `json:"service"`
	}

	var ustr string
	if strings.HasPrefix(did, "did:plc:") {
		ustr = fmt.Sprintf("https://plc.directory/%s", did)
	} else if strings.HasPrefix(did, "did:web:") {
		ustr = fmt.Sprintf("https://%s/.well-known/did.json", strings.TrimPrefix(did, "did:web:"))
	} else {
		return "", "", fmt.Errorf("did was not a supported did type")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", ustr, nil)
	if err != nil {
		return "", "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return "", "", fmt.Errorf("could not find identity in plc registry")
	}

	var identity Identity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return "", "", err
	}

	var service string
	for _, svc := range identity.Service {
		if svc.ID == "#atproto_pds" {
			service = svc.ServiceEndpoint
		}
	}

	if service == "" {
		return "", "", fmt.Errorf("could not find atproto_pds service in identity services")
	}

	handle := did
	if len(identity.AlsoKnownAs) > 0 {
		handle = identity.AlsoKnownAs[0]
		if !strings.HasPrefix(handle, "at://") {
			return "", "", fmt.Errorf("handle is not a valid atproto handle: %s", handle)
		}
		handle = strings.TrimPrefix(handle, "at://")
	}

	return service, handle, nil
}

// returns did, service
func ResolveHandleAndServiceWithClient(ctx context.Context, handle string, client *http.Client) (string, string, *echo.HTTPError) {
	did, err := ResolveHandleWithClient(ctx, handle, client)
	if err != nil {
		return "", "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to resolve handle '%s': %s", handle, err))
	}

	var handle2 string
	service, handle2, err := ResolveServiceWithClient(ctx, did, client)
	if err != nil {
		return "", "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to resolve service for DID '%s': %s", did, err))
	}
	if handle2 != handle {
		return "", "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("handle mismatch: %s != %s", handle2, handle))
	}
	return did, service, nil
}

func (o *OATProxy) HandleComAtprotoIdentityResolveHandle(c echo.Context) error {
	ctx, span := otel.Tracer("server").Start(c.Request().Context(), "HandleComAtprotoIdentityResolveHandle")
	defer span.End()
	handle := c.QueryParam("handle")
	var out *comatprototypes.IdentityResolveHandle_Output
	var handleErr error
	// func (s *Server) handleComAtprotoIdentityResolveHandle(ctx context.Context,handle string) (*comatprototypes.IdentityResolveHandle_Output, error)
	out, handleErr = handleComAtprotoIdentityResolveHandle(ctx, handle, o.httpClient)
	if handleErr != nil {
		return handleErr
	}
	return c.JSON(200, out)
}

func handleComAtprotoIdentityResolveHandle(ctx context.Context, handle string, client *http.Client) (*comatprototypes.IdentityResolveHandle_Output, error) {
	did, err := ResolveHandleWithClient(ctx, handle, client)
	if err != nil {
		return nil, err
	}
	return &comatprototypes.IdentityResolveHandle_Output{Did: did}, nil
}
