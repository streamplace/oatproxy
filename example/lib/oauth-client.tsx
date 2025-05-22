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
