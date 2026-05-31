import { Sdk } from "../dist/index.js";

const ORG_ID = process.env.HARDPOINT_ORG_ID;
if (!ORG_ID) {
  console.error("HARDPOINT_ORG_ID environment variable is required");
  process.exit(1);
}

const sdk = Sdk.init({ orgId: ORG_ID });
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
