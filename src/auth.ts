/**
 * Cross-framework abstraction for a lookup facility on incoming HTTP request headers.
 */
export interface HeaderProvider {
  /**
   * Attempt to look up a header value in the incoming request.
   *
   * @param name name of HTTP header. Case-insensitive.
   * @returns the first value of a given HTTP header in a request, or undefined if the header is not present
   */
  get(name: string): string | undefined;
}

/**
 * Cross-framework abstraction for an incoming HTTP request.
 */
export interface RequestContext {
  /**
   * Framework-specific {@link HeaderProvider}
   */
  headers: HeaderProvider
}

/**
 * Cross-runtime abstraction for deriving an auth token.
 *
 * An auth token may or may not use the current HTTP request context (e.g. for reading headers)
 */
export type TokenProvider = (ctx: RequestContext) => Promise<string | undefined>;

// OIDC token lookup for Vercel runtime environment
const vercelTokenProvider: TokenProvider = async (ctx: RequestContext) => {
  return ctx.headers.get("x-vercel-oidc-token") ?? process.env.VERCEL_OIDC_TOKEN;
}

// OIDC token lookup for GitHub Actions runner environment
const gitHubTokenProvider: TokenProvider = async (_: RequestContext) => {
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestToken) {
    console.log("ACTIONS_ID_TOKEN_REQUEST_TOKEN not present in environment");
    return undefined;
  }

  const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  if (!requestUrl) {
    console.log("ACTIONS_ID_TOKEN_REQUEST_URL not present in environment");
    return undefined;
  }

  try {
    const response = await fetch(requestUrl, {
      method: "POST",
      body: "{}",
      headers: {
        'Authorization': `Bearer ${requestToken}`,
        'Accept': "application/json; api-version=2.0",
        'Content-Type': 'application/json',
      },
    });
    if (!response.ok) {
      console.log(
        `OIDC token request failed: ${response.status} ${response.statusText}`
      );
      return undefined;
    }
    const data = await response.json() as { value?: string };
    if (!data.value) {
      console.log("OIDC token response missing 'value' field");
      return undefined;
    }
    return data.value;
  } catch (err) {
    console.log(`OIDC token request error: ${err}`);
    return undefined;
  }
}

const providerChain = [vercelTokenProvider, gitHubTokenProvider];

/**
 * A composite chain of underlying TokenProvider implementations.
 *
 * Attempts to derive a token from multiple implementations until either a token is found or no more implementations are available.
 *
 * @param ctx {@link RequestContext} object
 * @returns chain of token provider implementations
 */
export const chainedTokenProvider: TokenProvider = async (ctx: RequestContext) => {
  for (const provider of providerChain) {
    const result = await provider(ctx);
    if (result) {
      return result;
    }
  }
  return undefined;
}
