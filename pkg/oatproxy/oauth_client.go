package oatproxy

import (
	oauth "github.com/streamplace/atproto-oauth-golang"
)

func (o *OATProxy) GetOauthClient() (*oauth.Client, error) {
	upstreamMeta := o.GetUpstreamMetadata()

	args := oauth.ClientArgs{
		ClientJwk:   o.upstreamJWK,
		ClientId:    upstreamMeta.ClientID,
		RedirectUri: upstreamMeta.RedirectURIs[0],
	}
	// A public (loopback) client authenticates with `none`: no assertion.
	// Strict authorization servers reject a private_key_jwt assertion from
	// a client_id whose implied metadata says `none`.
	if o.public {
		args.ClientJwk = nil
	}
	return oauth.NewClient(args)
}
