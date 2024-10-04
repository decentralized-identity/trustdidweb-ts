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

4. `test:watch`: Run tests in watch mode, focusing on witness tests.
   ```bash
   bun run test:watch
   ```
   This command runs: `bun test --watch witness`

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

## CLI Documentation

```
The CLI is Experimental, buggy and beta software -- use at your own risk!
```

The trustdidweb-ts package provides a Command Line Interface (CLI) for managing Decentralized Identifiers (DIDs) using the `did:tdw` method.


### Usage

The general syntax for using the CLI is:

```bash
bun run cli [command] [options]
```

To output the help using the CLI:

```bash
bun run cli help
```

### Commands

1. **Create a DID**

   ```bash
   bun run cli create [options]
   ```

   Options:
   - `--domain [domain]`: (Required) Domain for the DID
   - `--output [file]`: (Optional) Path to save the DID log
   - `--portable`: (Optional) Make the DID portable
   - `--prerotation`: (Optional) Enable pre-rotation
   - `--witness [witness]`: (Optional) Add a witness (can be used multiple times)
   - `--witness-threshold [n]`: (Optional) Set witness threshold

   Example:
   ```bash
   bun run cli create --domain example.com --portable --witness did:tdw:QmWitness1:example.com --witness did:tdw:QmWitness2...:example.com
   ```

2. **Resolve a DID**

   ```bash
   bun run cli resolve --did [did]
   ```

   Example:
   ```bash
   bun run cli resolve --did did:tdw:Qm...:example.com
   ```

3. **Update a DID**

   ```bash
   bun run cli update [options]
   ```

   Options:
   - `--log [file]`: (Required) Path to the DID log file
   - `--output [file]`: (Optional) Path to save the updated DID log
   - `--prerotation`: (Optional) Enable pre-rotation
   - `--witness [witness]`: (Optional) Add a witness (can be used multiple times)
   - `--witness-threshold [n]`: (Optional) Set witness threshold
   - `--service [service]`: (Optional) Add a service (format: type,endpoint)
   - `--add-vm [type]`: (Optional) Add a verification method
   - `--also-known-as [alias]`: (Optional) Add an alsoKnownAs alias

   Example:
   ```bash
   bun run cli update --log ./did.jsonl --output ./updated-did.jsonl --add-vm keyAgreement --service LinkedDomains,https://example.com
   ```

4. **Deactivate a DID**

   ```bash
   bun run cli deactivate [options]
   ```

   Options:
   - `--log [file]`: (Required) Path to the DID log file
   - `--output [file]`: (Optional) Path to save the deactivated DID log

   Example:
   ```bash
   bun run cli deactivate --log ./did.jsonl --output ./deactivated-did.jsonl
   ```

### Additional Notes

- The CLI automatically generates new authentication keys when creating or updating a DID.
- The `--portable` option in the create command allows the DID to be moved to a different domain later.
- The `--prerotation` option enables key pre-rotation, which helps prevent loss of control if an active private key is compromised.
- Witness functionality allows for third-party attestation of DID operations.
- The CLI saves the DID log to a file when the `--output` option is provided.
- For the update and deactivate commands, the existing DID log must be provided using the `--log` option.
