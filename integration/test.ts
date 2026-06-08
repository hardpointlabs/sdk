import { Sdk } from "@hardpointlabs/sdk";
import { consoleLogger } from "@hardpointlabs/sdk/logging";
import * as http from 'node:http';

const sdk = Sdk.init({orgId: process.env.HARDPOINT_ORG_ID!, logger: consoleLogger('trace')});
const mockRequestContext = {
  headers: { get: () => undefined }
}

await using tunnel = await sdk.connect("hello", mockRequestContext);

const response = await new Promise<{ status: number; body: string }>(
  (resolve, reject) => {
    const req = http.request(
      {
        createConnection: () => tunnel.asSocket(),
        path: "/",
        method: "GET",
        host: "example.com",
        port: 80,
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

process.exit(0);
