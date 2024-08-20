import { createDID, resolveDID, updateDID, deactivateDID } from './method';
import { createSigner, generateEd25519VerificationMethod } from './cryptography';
import { readLogFromDisk, writeLogToDisk } from './utils';

const usage = `
Usage: bun run cli -- [command] [options]

Commands:
  create   Create a new DID
  resolve  Resolve a DID
  update   Update an existing DID
  deactivate Deactivate an existing DID

Options:
  --domain [domain]     Domain for the DID (required for create)
  --log [file]          Path to the DID log file (required for resolve, update, deactivate)
  --output [file]       Path to save the updated DID log (optional for create, update, deactivate)

Examples:
  bun run cli -- create --domain example.com
  bun run cli -- resolve --log ./did.jsonl
  bun run cli -- update --log ./did.jsonl --output ./updated-did.jsonl
  bun run cli -- deactivate --log ./did.jsonl --output ./deactivated-did.jsonl
`;

async function main() {
  const args = Bun.argv.slice(2);  // Use Bun.argv instead of process.argv
  const command = args[0];

  if (!command) {
    console.log(usage);
    process.exit(1);
  }

  try {
    switch (command) {
      case 'create':
        await handleCreate(args.slice(1));
        break;
      case 'resolve':
        await handleResolve(args.slice(1));
        break;
      case 'update':
        await handleUpdate(args.slice(1));
        break;
      case 'deactivate':
        await handleDeactivate(args.slice(1));
        break;
      default:
        console.log(`Unknown command: ${command}`);
        console.log(usage);
        process.exit(1);
    }
  } catch (error) {
    console.error('An error occurred:', error);
    process.exit(1);
  }
}

async function handleCreate(args: string[]) {
  const domainIndex = args.findIndex(arg => arg === '--domain');
  const outputIndex = args.findIndex(arg => arg === '--output');

  const domain = domainIndex !== -1 && args[domainIndex + 1] ? args[domainIndex + 1] : undefined;
  const output = outputIndex !== -1 && args[outputIndex + 1] ? args[outputIndex + 1] : undefined;

  if (!domain) {
    console.error('Domain is required for create command');
    process.exit(1);
  }

  const authKey = await generateEd25519VerificationMethod('authentication');
  const { did, doc, meta, log } = await createDID({
    domain,
    signer: createSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: [authKey],
  });

  console.log('Created DID:', did);
  console.log('DID Document:', JSON.stringify(doc, null, 2));
  console.log('Meta:', JSON.stringify(meta, null, 2));

  if (output) {
    writeLogToDisk(output, log);
    console.log(`DID log written to ${output}`);
  }
}

async function handleResolve(args: string[]) {
  const logIndex = args.findIndex(arg => arg === '--log');
  const logFile = logIndex !== -1 && args[logIndex + 1] ? args[logIndex + 1] : undefined;

  if (!logFile) {
    console.error('Log file is required for resolve command');
    process.exit(1);
  }

  const log = readLogFromDisk(logFile);
  const { did, doc, meta } = await resolveDID(log);

  console.log('Resolved DID:', did);
  console.log('DID Document:', JSON.stringify(doc, null, 2));
  console.log('Metadata:', meta);
}

async function handleUpdate(args: string[]) {
  const logIndex = args.findIndex(arg => arg === '--log');
  const outputIndex = args.findIndex(arg => arg === '--output');

  const logFile = logIndex !== -1 && args[logIndex + 1] ? args[logIndex + 1] : undefined;
  const output = outputIndex !== -1 && args[outputIndex + 1] ? args[outputIndex + 1] : undefined;

  if (!logFile) {
    console.error('Log file is required for update command');
    process.exit(1);
  }

  const log = readLogFromDisk(logFile);
  const authKey = await generateEd25519VerificationMethod('authentication');
  const { did, doc, meta, log: updatedLog } = await updateDID({
    log,
    signer: createSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: [authKey],
  });

  console.log('Updated DID:', did);
  console.log('Updated DID Document:', JSON.stringify(doc, null, 2));

  if (output) {
    writeLogToDisk(output, updatedLog);
    console.log(`Updated DID log written to ${output}`);
  }
}

async function handleDeactivate(args: string[]) {
  const logIndex = args.findIndex(arg => arg === '--log');
  const outputIndex = args.findIndex(arg => arg === '--output');

  const logFile = logIndex !== -1 && args[logIndex + 1] ? args[logIndex + 1] : undefined;
  const output = outputIndex !== -1 && args[outputIndex + 1] ? args[outputIndex + 1] : undefined;

  if (!logFile) {
    console.error('Log file is required for deactivate command');
    process.exit(1);
  }

  const log = readLogFromDisk(logFile);
  const authKey = await generateEd25519VerificationMethod('authentication');
  const { did, doc, meta, log: deactivatedLog } = await deactivateDID({
    log,
    signer: createSigner(authKey),
  });

  console.log('Deactivated DID:', did);
  console.log('Deactivated DID Document:', JSON.stringify(doc, null, 2));

  if (output) {
    writeLogToDisk(output, deactivatedLog);
    console.log(`Deactivated DID log written to ${output}`);
  }
}

main();