package oatproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
	"github.com/streamplace/atproto-oauth-golang/helpers"
)

func (o *OATProxy) HandleOAuthAuthorizationServer(c echo.Context) error {
	c.Response().Header().Set("Access-Control-Allow-Origin", "*")
	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().WriteHeader(200)
	json.NewEncoder(c.Response().Writer).Encode(generateOAuthServerMetadata(o.host))
	return nil
}

func (o *OATProxy) HandleOAuthProtectedResource(c echo.Context) error {
	return c.JSON(200, map[string]interface{}{
		"resource": fmt.Sprintf("https://%s", o.host),
		"authorization_servers": []string{
			fmt.Sprintf("https://%s", o.host),
		},
		"scopes_supported": []string{},
		"bearer_methods_supported": []string{
			"header",
		},
		"resource_documentation": "https://atproto.com",
	})
}

func (o *OATProxy) HandleClientMetadataUpstream(c echo.Context) error {
	meta := o.GetUpstreamMetadata()
	return c.JSON(200, meta)
}

func (o *OATProxy) HandleJwksUpstream(c echo.Context) error {
	pubKey, err := o.upstreamJWK.PublicKey()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not get public key")
	}
	return c.JSON(200, helpers.CreateJwksResponseObject(pubKey))
}

func (o *OATProxy) HandleClientMetadataDownstream(c echo.Context) error {
	redirectURI := c.QueryParam("redirect_uri")
	meta, err := o.GetDownstreamMetadata(redirectURI)
	if err != nil {
		return err
	}
	return c.JSON(200, meta)
}

func (o *OATProxy) GetUpstreamMetadata() *OAuthClientMetadata {
	meta := *o.clientMetadata
	meta.ClientID = fmt.Sprintf("https://%s/oauth/upstream/client-metadata.json", o.host)
	meta.JwksURI = fmt.Sprintf("https://%s/oauth/upstream/jwks.json", o.host)
	meta.ClientURI = fmt.Sprintf("https://%s", o.host)
	meta.TokenEndpointAuthMethod = "private_key_jwt"
	meta.ResponseTypes = []string{"code"}
	meta.GrantTypes = []string{"authorization_code", "refresh_token"}
	meta.DPoPBoundAccessTokens = boolPtr(true)
	meta.TokenEndpointAuthSigningAlg = "ES256"
	meta.RedirectURIs = []string{fmt.Sprintf("https://%s/oauth/return", o.host)}
	return &meta
}

func generateOAuthServerMetadata(host string) map[string]any {
	oauthServerMetadata := map[string]any{
		"issuer":                                         fmt.Sprintf("https://%s", host),
		"request_parameter_supported":                    true,
		"request_uri_parameter_supported":                true,
		"require_request_uri_registration":               true,
		"scopes_supported":                               []string{"atproto", "transition:generic", "transition:chat.bsky"},
		"subject_types_supported":                        []string{"public"},
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query", "fragment", "form_post"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"ui_locales_supported":                           []string{"en-US"},
		"display_values_supported":                       []string{"page", "popup", "touch"},
		"authorization_response_iss_parameter_supported": true,
		"request_object_encryption_alg_values_supported": []string{},
		"request_object_encryption_enc_values_supported": []string{},
		"jwks_uri":                              fmt.Sprintf("https://%s/oauth/jwks", host),
		"authorization_endpoint":                fmt.Sprintf("https://%s/oauth/authorize", host),
		"token_endpoint":                        fmt.Sprintf("https://%s/oauth/token", host),
		"token_endpoint_auth_methods_supported": []string{"none", "private_key_jwt"},
		"revocation_endpoint":                   fmt.Sprintf("https://%s/oauth/revoke", host),
		"introspection_endpoint":                fmt.Sprintf("https://%s/oauth/introspect", host),
		"pushed_authorization_request_endpoint": fmt.Sprintf("https://%s/oauth/par", host),
		"require_pushed_authorization_requests": true,
		"client_id_metadata_document_supported": true,
		"request_object_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
			"ES256", "ES256K", "ES384", "ES512", "none",
		},
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
			"ES256", "ES256K", "ES384", "ES512",
		},
		"dpop_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
			"ES256", "ES256K", "ES384", "ES512",
		},
	}
	return oauthServerMetadata
}

func (o *OATProxy) GetDownstreamMetadata(redirectURI string) (*OAuthClientMetadata, error) {
	meta := *o.clientMetadata
	meta.ClientID = fmt.Sprintf("https://%s/oauth/downstream/client-metadata.json", o.host)
	meta.ClientURI = fmt.Sprintf("https://%s", o.host)
	meta.TokenEndpointAuthMethod = "none"
	meta.ResponseTypes = []string{"code"}
	meta.GrantTypes = []string{"authorization_code", "refresh_token"}
	meta.DPoPBoundAccessTokens = boolPtr(true)
	meta.ApplicationType = "web"
	if redirectURI != "" {
		// found := false
		// lie, err := redirectLiar(redirectURI, meta.ClientURI)
		// if err != nil {
		// 	return nil, err
		// }
		// for _, uri := range meta.RedirectURIs {
		// 	if uri == lie {
		// 		found = true
		// 		break
		// 	}
		// }
		// if !found {
		// 	return nil, echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid redirect_uri: %s not in the allowed URIs", redirectURI))
		// }
		meta.RedirectURIs = []string{redirectURI}
	}

	for i, uri := range meta.RedirectURIs {
		lie, err := redirectLiar(uri, meta.ClientURI)
		if err != nil {
			return nil, err
		}
		meta.RedirectURIs[i] = lie
	}

	return &meta, nil
}

const REDIRECT_LIAR_QUERY_PARAM = "oatproxyActualRedirect"

func redirectLiar(redirectURI string, clientURI string) (string, error) {
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid redirect_uri: %s", redirectURI))
	}
	clientURL, err := url.Parse(clientURI)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid client_uri: %s", clientURI))
	}

	if redirectURL.Host == clientURL.Host {
		return redirectURI, nil
	}

	// When redirect URI host doesn't match client URI host, create a special redirect URL
	// that points to the client host with the actual redirect as a query parameter
	encodedRedirect := url.QueryEscape(redirectURI)
	return fmt.Sprintf("https://%s?%s=%s", clientURL.Host, REDIRECT_LIAR_QUERY_PARAM, encodedRedirect), nil
}

// redirectTruther detects if a URL contains an actualRedirect query parameter
// and returns the real redirect URL if found, otherwise returns the original URL unchanged
func redirectTruther(redirectURI string) (string, error) {
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid redirect_uri: %s", redirectURI))
	}

	// Check if the URL has an actualRedirect query parameter
	actualRedirect := redirectURL.Query().Get(REDIRECT_LIAR_QUERY_PARAM)
	if actualRedirect == "" {
		// No actualRedirect parameter, return the original URL
		return redirectURI, nil
	}

	// Decode the actualRedirect parameter
	decodedRedirect, err := url.QueryUnescape(actualRedirect)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid actualRedirect parameter: %s", actualRedirect))
	}

	// Validate that the decoded redirect is a valid URL
	_, err = url.Parse(decodedRedirect)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid actualRedirect URL: %s", decodedRedirect))
	}

	return decodedRedirect, nil
}
