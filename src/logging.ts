const logLevelOrder = ['trace', 'debug', 'info', 'warn', 'error'] as const;

/**
 * Severity tags used to filter & prioritize log messages.
 */
export type LogLevel = typeof logLevelOrder[number];

const levelRanking = Object.fromEntries(
  logLevelOrder.map((v, i) => [v, i])
) as Record<LogLevel, number>;

/**
 * Any objects you wish to add to a log event.
 */
export type LogProps = Record<string, unknown>;

/**
 * The base type that all log calls in the SDK interact with.
 */
export interface Logger {
  trace(msg: string, props?: LogProps): void;
  debug(msg: string, props?: LogProps): void;
  info(msg: string, props?: LogProps): void;
  warn(msg: string, props?: LogProps): void;
  error(msg: string, props?: LogProps): void;
}

/**
 * Simple default Logger implementation that does nothing when called.
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

/**
 * Create a Logger which internally wraps the console object.
 *
 * @internal
 */
export function consoleLogger(minLevel: LogLevel = 'debug'): Logger {
  const log = (level: LogLevel, msg: string, props?: Record<string, unknown>) => {
    if (levelRanking[level] < levelRanking[minLevel]) return;
    const line = JSON.stringify({ ts: Date.now(), level, msg, ...props });
    (level === 'error' || level === 'warn' ? console.error : console.log)(line);
  };
  return {
    trace: (msg, meta) => log('trace', String(msg), meta),
    debug: (msg, meta) => log('debug', String(msg), meta),
    info:  (msg, meta) => log('info', msg, meta),
    warn:  (msg, meta) => log('warn', msg, meta),
    error: (msg, meta) => log('error', msg, meta),
  };
}