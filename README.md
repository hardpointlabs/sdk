# SDK

![NPM Version](https://img.shields.io/npm/v/%40hardpointlabs%2Fsdk)
![Discord](https://img.shields.io/discord/1481682538291400758)

The SDK connects serverless functions to your services. It's compatible with JavaScript and TypeScript projects running on node 22 or greater.

> [!TIP]
> Note! This is early alpha, Reach out directly on [discord](https://discord.gg/WWE4PWVnb2) or [X](https://x.com/h7tlabs) if you need help and we'll respond!

---

# Getting started

## Prerequisites

1. A Hardpoint account and valid Org ID: [Sign up for free](https://dashboard.hardpoint.dev) to get one
2. A JavaScript/TypeScript project running on Vercel
3. The an [agent configured](https://docs.hardpoint.dev/hardpoint-connect/getting-started/set-up-the-agent) to expose at least one service

## Installation

The SDK can be installed like any other npm module:

```bash
npm i --save @hardpointlabs/sdk
```

## Setup

Import the SDK and initialize it *once* when your application starts up:

```typescript
import { Sdk } from '@hardpointlabs/sdk'

// if you don't specify org id here, the SDK will
// fall back to the HARDPOINT_ORG_ID env var
const sdk = Sdk.init({org_id: '<YOUR_ORG_ID>'})
```

Now you can connect to a service:

```typescript
await using tunnel = sdk.connect('postgres.prod')
// pass {tunnel} to your postgres client
```

## Next steps

* See [client-specific examples](https://docs.hardpoint.dev/hardpoint-connect/sdk-integration-examples) in the docs
* The full SDK API docs are [here](https://sdk.hardpoint.dev)
