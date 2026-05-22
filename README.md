# SDK

![NPM Version](https://img.shields.io/npm/v/%40hardpointlabs%2Fsdk)
![Discord](https://img.shields.io/discord/1481682538291400758)

The SDK integrates your application code with Hardpoint Connect. It's compatible with server-side JavaScript and TypeScript projects running on node 22 or greater.

---

# Getting started

## Prerequisites

1. A Hardpoint account and valid Org ID: [Sign up for free](https://dashboard.hardpoint.dev) to get one
2. A JavaScript/TypeScript project running on Vercel
3. An [agent configured](https://docs.hardpoint.dev/hardpoint-connect/getting-started/set-up-the-agent) to expose at least one service

## Installation

The SDK can be installed like any other npm module:

```bash
npm i --save @hardpointlabs/sdk
```

## Setup

Import the SDK and initialize it *once* when your application starts up:

```typescript
import { Sdk } from '@hardpointlabs/sdk'

// Specify your Hardpoint Org ID
const sdk = Sdk.init({orgId: '<YOUR_ORG_ID>'})
```

Now you can connect to a service:

```typescript
// ctx is a RequestContext object
await using tunnel = sdk.connect('postgres.prod', ctx)
// pass {tunnel} to your postgres client
```

## Next steps

* See [client-specific examples](https://docs.hardpoint.dev/hardpoint-connect/sdk-integration-examples) in the docs
* The full SDK API docs are [here](https://sdk.hardpoint.dev)
