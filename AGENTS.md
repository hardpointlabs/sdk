# AGENTS instructions

## Overview

This repo contains the Hardpoint SDK, an ES module which is designed to be integrated into a users' application in order for it to communicate with their private Hardpoint network. For more information about how this fits into the Hardpoint ecosystem consult the [org readme](https://github.com/hardpointlabs/.github/blob/main/profile/README.md).

It is responsible for:

- Authentication: obtaining credentials from the runtime environment to auth into Hardpoint network (e.g. Vercel-injected OIDC token)
- Setting up a tunnel to a remote service, in the form of an HTTP CONNECT request. The remote host it directly connects to is colloquially known as the 'relay'. Behind it is a few moving parts but that's opaque to the user; the important thing is
- Doing the client-side of the end-to-end encryption dance using [ML-KEM](https://en.wikipedia.org/wiki/ML-KEM) to ensure that traffic passing through the Hardpoint relay is always encrypted and therefore private, even if the underlying traffic isn't, and transparently encrypting/decrypting everything going across the wire
- Exposing integration points to established tunnels for common client libraries to use

It's optimized to discover OIDC tokens from several runtime environments such as [Vercel](https://vercel.com), [Fly.io](https://fly.io) and [Github Actions runners](https://docs.github.com/en/actions)

## Environment setup

- The SDK targets modern nodejs (at least 22) and aims to support the last 2 LTS versions, plus Bun and Deno
- It's a standard NPM package
- Implementation is 100% TypeScript (currently using major version 6)
- Uses TypeDoc to generate documentation
- Uses [FTA](https://ftaproject.dev) for static analysis of TypeScript source

## Repo layout

- `packages/sdk`: The SDK package (`@hardpointlabs/sdk`), contains:
  - `src/`: Main implementation directory, all TypeScript files
  - `dist/`: Output directory of compiled TS and type definitions
  - `lib/`: Anciliary support files; currently this only contains a copy of the Root CA certificate which the relay's PKI uses (when the SDK establishes a tunnel, the first thing it does is set up a TLS connection. Instead of using the standard certificate bundle, it should *only* trust remote certs signed by this Root CA). This file is copied into the `dist` directory for use at runtime. Other similar support files should live here and be copied accordingly during `build`
  - `integration/`: Integration test harness that installs the SDK from a tarball and exercises it against the live relay
- Other packages may be added under `packages/` as the monorepo grows

## Coding standards & established conventions

- Avoid changing any public API surfaces (i.e. public methods/accessors of the `Sdk` class and the associated types that are not documented as internal)
- The SDK has an intentionally light footprint: it has 2 direct dependencies, one (`@hardpointlabs/length-prefixed-stream`) which we control, used for framing tunnel messages. We can make changes to this code if necessary. The other (`mlkem`) which is necessary to derive a shared secret and ciphertext to complete the ML-KEM handshake. Avoid adding other libraries to the list of _runtime_ dependencies ('dependencies' in package.json)
- You _may_ add more dev dependencies if it is strictly necessary ('devDependencies' in package.json)
- Stick to implementing functionality in TypeScript
- Since this is a widely deployed SDK, use semicolons at line endings
- 2 spaces for tabs
- Trim any trailing whitespace at the end of lines

## Workflow

1. Run `npm run build`, ensure this is working
2. The most common possible failures of the build are TypeScript compilation errors, or quality degredations in FTA. Refactor any changes as necessary (without altering the public API surface), and re-run the build step until the quality arrives at an `OK` value. You can see more specifics regarding static analyzer metrics for each file by running `npx fta-cli . --json` from the project root.
