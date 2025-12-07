package oatproxy

import (
	oauth "github.com/streamplace/atproto-oauth-golang"
)

func (o *OATProxy) GetOauthClient() (*oauth.Client, error) {
	upstreamMeta := o.GetUpstreamMetadata()

	return oauth.NewClient(oauth.ClientArgs{
		ClientJwk:   o.upstreamJWK,
		ClientId:    upstreamMeta.ClientID,
		RedirectUri: upstreamMeta.RedirectURIs[0],
	})
}
