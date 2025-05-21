# OATProxy: An ATProto OAuth Proxy

**ALPHA SOFTWARE, USE AT YOUR OWN RISK! LOTS MORE TO COME IN THE NEXT WEEK!**

Tired of getting logged out of your AT Protocol applications every 48 hours?
Introducing OATProxy! OATProxy acts as a transparent passthrough XRPC proxy
between your front-end application, upgrading your users from
frequently-expiring "public" OAuth sessions to robust, hearty "confidential"
OAuth sessions.

| Session Type | Inactivity Timeout | Max Session Length |
| ------------ | ------------------ | ------------------ |
| Public       | 2 days             | 7 days             |
| Confidential | 1 month            | 1 year             |

OATProxy exists as both a Go library for embedding in applications and as a
standalone microservice.

# Prerequisites

You'll need:

- A public HTTPS address that forwards to this server. (Built-in TLS is coming!)
- A `client-metadata.json` file. You can customize the
  `client-metadata.example.json` file in this repo.
- An ATProto app that already works with "public" OAuth.

# Installing

```
go install github.com/streamplace/oatproxy/cmd/oatproxy@latest
```

# Running

```
oatproxy --host=example.com --client-metadata=client-metadata.json
```

The server will then be available to handle requests on port 8080.

Optionally, OATProxy can operate as a reverse proxy for another application
server behind it with the `--upstream-host` parameter. If you operate in this
mode, OATProxy will handle all requests for `/oauth`, `/xrpc`, and the OAuth
documents in `/.well-known`. All other requests will be proxied upstream.

# Usage with `@atproto/oauth-client-browser`

(This also applies to `@streamplace/oauth-client-react-native`.)

For this to work, you're going to have to tell some lies. Specifically, you're
going to need to tell `@atproto/oauth-client-browser` that, no matter who the
user is, their PDS URL is OATProxy's URL. This can be accomplished by overriding
the `fetch` handler passed to the client:

```typescript
import { BrowserOAuthClient, OAuthClient } from "@atproto/oauth-client-browser";

const fetchWithLies = async (
  oatProxyUrl: string,
  input: RequestInfo | URL,
  init?: RequestInit
) => {
  // Normalize input to a Request object
  let request: Request;
  if (typeof input === "string" || input instanceof URL) {
    request = new Request(input, init);
  } else {
    request = input;
  }

  if (
    request.url.includes("plc.directory") || // did:plc
    request.url.endsWith("did.json") // did:web
  ) {
    const res = await fetch(request, init);
    if (!res.ok) {
      return res;
    }
    const data = await res.json();
    const service = data.service.find((s: any) => s.id === "#atproto_pds");
    if (!service) {
      return res;
    }
    service.serviceEndpoint = oatProxyUrl;
    return new Response(JSON.stringify(data), {
      status: res.status,
      headers: res.headers,
    });
  }

  return fetch(request, init);
};

export default async function createOAuthClient(
  oatProxyUrl: string
): Promise<OAuthClient> {
  return await BrowserOAuthClient.load({
    clientId: `${oatProxyUrl}/oauth/downstream/client-metadata.json`,
    handleResolver: oatProxyUrl,
    responseMode: "query",

    // Lie to the oauth client and use our upstream server instead
    fetch: (input, init) => fetchWithLies(oatProxyUrl, input, init),
  });
}
```

# Partial List of Endpoints

These can be useful for debugging purposes:

| URL                                      | Description                                                                    |
| ---------------------------------------- | ------------------------------------------------------------------------------ |
| `/oauth/downstream/client-metadata.json` | "Public" client metadata document presented to the "downstream" browser client |
| `/oauth/upstream/client-metadata.json`   | "Confidential" client metadata presented to the "upstream" PDS                 |

# Building

```
make
```

# TODO

- Many tests
- Built-in TLS support
- Simple local example
- Docker image
- Postgres support
- Document usage as a library
- Document usage on a worker of some kind
- Document usage with atcute
- Ship `@streamplace/atproto-oauth-client-isomorphic` that tells lies
  automatically

# Credits

This library brought to you by
[Streamplace](https://github.com/streamplace/streamplace).
["Upstream" Go ATProto OAuth client forked from haileyok](https://github.com/haileyok/atproto-oauth-golang).
