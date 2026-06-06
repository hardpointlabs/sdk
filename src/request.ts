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
