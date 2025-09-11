package oatproxy

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/AxisCommunications/go-dpop"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func boolPtr(b bool) *bool {
	return &b
}

func codeUUID(prefix string) string {
	uu, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s-%s", prefix, uu.String())
}

var urnPrefix = "urn:ietf:params:oauth:request_uri:"

const UUID_LENGTH = 37

func makeURN(jkt string) string {
	uu, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s%s-%s", urnPrefix, uu.String(), jkt)
}

// urn --> jkt, uu
func parseURN(urn string) (string, string, error) {
	if !strings.HasPrefix(urn, urnPrefix) {
		return "", "", fmt.Errorf("invalid URN: %s", urn)
	}
	withoutPrefix := urn[len(urnPrefix):]
	uu := withoutPrefix[:UUID_LENGTH]
	suffix := withoutPrefix[UUID_LENGTH:]
	return suffix, uu, nil
}

func makeState(jkt string) string {
	uu, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s-%s", uu.String(), jkt)
}

func parseState(state string) (string, string, error) {
	if len(state) < UUID_LENGTH {
		return "", "", fmt.Errorf("invalid state: %s", state)
	}
	uu := state[:UUID_LENGTH]
	suffix := state[UUID_LENGTH:]
	return suffix, uu, nil
}

func makeNoncePad() string {
	uu, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("noncepad-%s", uu.String())
}

// returns jkt, nonce, error
func getJKT(dpopJWT string) (string, *dpop.ProofTokenClaims, error) {
	var claims dpop.ProofTokenClaims
	token, err := jwt.ParseWithClaims(dpopJWT, &claims, keyFunc)
	if err != nil {
		return "", nil, err
	}
	jwk, ok := token.Header["jwk"].(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("missing jwk in DPoP JWT header")
	}
	jwkJSONbytes, err := getThumbprintableJwkJSONbytes(jwk)
	if err != nil {
		// keyFunc used with parseWithClaims should ensure that this can not happen but better safe than sorry.
		return "", nil, errors.Join(dpop.ErrInvalidProof, err)
	}
	h := sha256.New()
	_, err = h.Write(jwkJSONbytes)
	if err != nil {
		return "", nil, errors.Join(dpop.ErrInvalidProof, err)
	}
	b64URLjwkHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return b64URLjwkHash, &claims, nil
}

func (o *OATProxy) authServerURL(session *OAuthSession, path string) *url.URL {
	if o.public {
		u, err := url.Parse(session.UpstreamAuthServerURL)
		if err != nil {
			panic(err)
		}
		return &url.URL{Host: u.Host, Scheme: u.Scheme, Path: path}
	} else {
		return &url.URL{Host: o.host, Scheme: "https", Path: path}
	}
}

func (o *OATProxy) pdsServerURL(session *OAuthSession, path string) *url.URL {
	if o.public {
		u, err := url.Parse(session.PDSUrl)
		if err != nil {
			panic(err)
		}
		return &url.URL{Host: u.Host, Scheme: u.Scheme, Path: path}
	} else {
		return &url.URL{Host: o.host, Scheme: "https", Path: path}
	}
}

// if you're not expecting a nonce, pass in an empty string
// but also, if you ARE expecting a nonce, error before you get here if one is not provided
func (o *OATProxy) validateDPoP(dpopHeader string, method dpop.HTTPVerb, path string) (*OAuthSession, *echo.HTTPError) {
	jkt, _, err := getJKT(dpopHeader)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("failed to get JKT from DPoP header header=%s: %s", dpopHeader, err))
	}
	session, err := o.getOAuthSession(jkt)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("could not get oauth session: %s", err))
	}
	if session == nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "session not found")
	}
	proof, err := dpop.Parse(dpopHeader, method, o.authServerURL(session, path), dpop.ParseOptions{
		Nonce:      "",
		TimeWindow: &dpopTimeWindow,
	})
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid DPoP proof: s", err)
	}
	if proof.PublicKey() != jkt {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "decode/proof JKT mismatch")
	}
	return session, nil
}

func compareURLs(url1, url2 string) bool {
	u1, err := url.Parse(url1)
	if err != nil {
		return false
	}
	u2, err := url.Parse(url2)
	if err != nil {
		return false
	}

	// Compare scheme, host, path, and fragment
	if u1.Scheme != u2.Scheme ||
		u1.Host != u2.Host ||
		u1.Path != u2.Path ||
		u1.Fragment != u2.Fragment {
		return false
	}

	// Compare query parameters (order doesn't matter)
	q1 := u1.Query()
	q2 := u2.Query()

	if len(q1) != len(q2) {
		return false
	}

	for key, values1 := range q1 {
		values2, exists := q2[key]
		if !exists {
			return false
		}
		if len(values1) != len(values2) {
			return false
		}
		// Compare values (order matters within each key's values)
		for i, v := range values1 {
			if v != values2[i] {
				return false
			}
		}
	}

	return true
}
