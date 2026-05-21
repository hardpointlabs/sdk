export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';

/**
 * The base type that all log calls in the SDK interact with.
 */
export interface Logger {
  trace(msg: any, meta?: Record<string, unknown>): void;
  debug(msg: any, meta?: Record<string, unknown>): void;
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
}

/**
 * Simple Logger implementation that does nothing when called.
 *
 * @internal
 */
export const noopLogger: Logger = {
  trace: () => {},
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};
