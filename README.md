# TrustedDID Web Typescript

trustdidweb-ts provides developers with a comprehensive library and resolver for working with Decentralized Identifiers (DIDs) following the `did:tdw` method specification. This Typescript-based toolkit is designed to facilitate the integration and management of DIDs within web applications, enabling secure identity verification and authentication processes. It includes functions for creating, resolving, updating and deactivating DIDs by managing DID documents. The package is built to ensure compatibility with the latest web development standards, offering a straightforward API that makes it easy to implement DID-based features in a variety of projects.

## Summary

The `trustdidweb-ts` implementation of the [`did:tdw`]('https://bcgov.github.io/trustdidweb') specification currently implements
the following features from the specification with the goal to be feature complete soon.

| Completed  | Feature | Details |
|------------|---------|---------|
| DONE       | Ongoing publishing of all DID Document (DIDDoc) versions for a DID | Includes publishing alongside a did:web DID/DIDDoc. |
| DONE       | The same DID-to-HTTPS transformation as did:web | - |
| DONE       | Ability to resolve the full history of the DID | Uses a verifiable chain of updates from genesis to deactivation. |
| DONE       | A self-certifying identifier (SCID) for the DID | Ensures global uniqueness, derived from the initial DIDDoc for portability. |
| DONE       | DIDDoc updates include a proof signed by the DID Controller(s) | Proof required for updates, authorized by the DID Controller(s). |
| TODO       | Optional mechanism for publishing “pre-rotation” keys | Helps prevent loss of control if an active private key is compromised. |
| TODO       | DID URL path handling | Defaults to resolve <did>/path/to/file by DID-to-HTTPS translation, can be overridden. |
| TODO       | A DID URL path <did>/whois | Automatically returns a Verifiable Presentation, if published by the DID controller. |


## Prerequisites

Install [bun.sh](https://bun.sh/)

```bash
curl -fsSL https://bun.sh/install | bash
```

## Install dependencies

```bash
bun install
```

## Run all tests

```bash
bun test
```

### Development mode

```bash
bun run test:watch
```

## Run the tests and save a log

```bash
bun run test:log
```
