#!/usr/bin/env node

import { Sdk } from "@hardpointlabs/sdk";
import type { Tunnel } from "@hardpointlabs/sdk/streams";
import type { RequestContext } from "@hardpointlabs/sdk/request";
import { consoleLogger } from "@hardpointlabs/sdk/logging";

const commands: Record<string, () => Promise<void>> = {
  start: async () => {
    console.log("Starting Hardpoint CLI...");

    const orgId = process.env.HARDPOINT_ORG_ID;
    if (!orgId) {
      console.error("HARDPOINT_ORG_ID environment variable is required");
      process.exit(1);
    }

    const mockRequestContext: RequestContext = {
      headers: { get: () => undefined },
    };

    const sdk = Sdk.init({ orgId, logger: consoleLogger("info") });
    const tunnel: Tunnel = await sdk.connect("hello", mockRequestContext);

    console.log(`Tunnel established: ${tunnel}`);
    console.log("Hardpoint CLI started successfully");
  },
};

const command = process.argv[2];
if (!command || !commands[command]) {
  console.error(`Usage: cli ${Object.keys(commands).join("|")}`);
  process.exit(1);
}

await commands[command]();
