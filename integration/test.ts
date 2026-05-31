import { Sdk } from "../dist/index.js";
import { Logger, LogLevel } from "../dist/logging.js";

const LEVELS = { trace: 0, debug: 1, info: 2, warn: 3, error: 4 };

function makeLogger(minLevel: LogLevel = 'debug'): Logger {
  const log = (level: LogLevel, msg: string, props?: Record<string, unknown>) => {
    if (LEVELS[level] < LEVELS[minLevel]) return;
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


const ORG_ID = process.env.HARDPOINT_ORG_ID;
if (!ORG_ID) {
  console.error("HARDPOINT_ORG_ID environment variable is required");
  process.exit(1);
}

const sdk = Sdk.init({ orgId: ORG_ID, logger:  makeLogger()});
const mockRequestContext = {
  headers: { get: () => undefined }
}

const tunnel = await sdk.connect("hello", mockRequestContext);

try {
  const http = await import("node:http");

  const response = await new Promise<{ status: number; body: string }>(
    (resolve, reject) => {
      const req = http.request(
        {
          createConnection: () => tunnel.asSocket(),
          path: "/",
          method: "GET",
          host: "hello",
          port: 8080,
        },
        (res) => {
          let body = "";
          res.on("data", (chunk: Buffer) => (body += chunk.toString()));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, body })
          );
        }
      );
      req.on("error", reject);
      req.setTimeout(15_000, () => {
        req.destroy(new Error("Request timed out after 15s"));
      });
      req.end();
    }
  );

  console.log(`Status: ${response.status}`);
  console.log(`Body: ${response.body}`);

  if (response.status !== 200) {
    console.error(
      `Integration test failed: expected 200, got ${response.status}`
    );
    process.exit(1);
  }

  console.log("Integration test passed!");
} finally {
  tunnel.destroy();
}
