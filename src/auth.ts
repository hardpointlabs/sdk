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

const vercelTokenProvider: TokenProvider = async (ctx: RequestContext) => {
  return ctx.headers.get("x-vercel-oidc-token") ?? process.env.VERCEL_OIDC_TOKEN;
}

/**
 * A composite chain of underlying TokenProvider implementations.
 *
 * Attempts to derive a token from multiple implementations until either a token is found or no more implementations are available.
 *
 * @param ctx {@type RequestContext} object
 * @returns chain of token provider implementations
 */
export const chainedTokenProvider: TokenProvider = async (ctx: RequestContext) => {
  return vercelTokenProvider(ctx);
}
