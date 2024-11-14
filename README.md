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
| DONE       | Optional mechanism for publishing "pre-rotation" keys | Helps prevent loss of control if an active private key is compromised. |
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

## Available Commands

The following commands are defined in the `package.json` file:

1. `dev`: Run the resolver in development mode with debugging enabled.
   ```bash
   bun run dev
   ```
   This command runs: `bun --watch --inspect-wait ./src/resolver.ts`

2. `server`: Run the resolver in watch mode for development.
   ```bash
   bun run server
   ```
   This command runs: `bun --watch ./src/resolver.ts`

3. `test`: Run all tests.
   ```bash
   bun run test
   ```
   This command runs: `bun test`

4. `test:watch`: Run tests in watch mode.
   ```bash
   bun run test:watch
   ```
   This command runs: `bun test --watch`

5. `test:bail`: Run tests in watch mode, stopping on the first failure with verbose output.
   ```bash
   bun run test:bail
   ```
   This command runs: `bun test --watch --bail --verbose`

6. `test:log`: Run tests and save the output to a log file.
   ```bash
   bun run test:log
   ```
   This command runs: `mkdir -p ./test/logs && LOG_RESOLVES=true bun test &> ./test/logs/test-run.txt`

7. `cli`: Run the CLI tool.
   ```bash
   bun run cli [command] [options]
   ```
   This command runs: `bun run src/cli.ts --`

## CLI Usage Guide

> ⚠️ **Warning**: The CLI is experimental beta software - use at your own risk!

### Basic Syntax
```bash
bun run cli [command] [options]
```

### Available Commands

#### 1. Create a DID
Create a new DID with various configuration options:

```bash
bun run cli create \
  --domain example.com \
  --output ./did.jsonl \
  --portable \
  --witness did:tdw:witness1:example.com \
  --witness-threshold 1
```

**Key Options:**
- `--domain`: (Required) Host domain for the DID
- `--output`: Save location for DID log
- `--portable`: Enable domain portability
- `--prerotation`: Enable key pre-rotation security
- `--witness`: Add witness DIDs (repeatable)
- `--witness-threshold`: Set minimum witness count
- `--next-key-hash`: Add pre-rotation key hashes (required with --prerotation)

#### 2. Resolve a DID
View the current state of a DID:

```bash
# From DID identifier
bun run cli resolve --did did:tdw:123456:example.com

# From local log file
bun run cli resolve --log ./did.jsonl
```

#### 3. Update a DID
Modify an existing DID's properties:

```bash
bun run cli update \
  --log ./did.jsonl \
  --output ./updated.jsonl \
  --add-vm keyAgreement \
  --service LinkedDomains,https://example.com \
  --also-known-as did:web:example.com
```

**Update Options:**
- `--log`: (Required) Current DID log path
- `--output`: Updated log save location
- `--add-vm`: Add verification methods:
  - authentication
  - assertionMethod
  - keyAgreement
  - capabilityInvocation
  - capabilityDelegation
- `--service`: Add services (format: type,endpoint)
- `--also-known-as`: Add alternative identifiers
- `--prerotation`: Enable/update key pre-rotation
- `--witness`: Update witness list
- `--witness-threshold`: Update witness requirements

#### 4. Deactivate a DID
Permanently deactivate a DID:

```bash
bun run cli deactivate \
  --log ./did.jsonl \
  --output ./deactivated.jsonl
```
