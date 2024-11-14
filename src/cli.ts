import { createDID, updateDID, deactivateDID, resolveDIDFromLog } from './method';
import { createSigner, generateEd25519VerificationMethod } from './cryptography';
import { fetchLogFromIdentifier, readLogFromDisk, writeLogToDisk, writeVerificationMethodToEnv } from './utils';
import { dirname } from 'path';
import fs from 'fs';

const usage = `
Usage: bun run cli [command] [options]

Commands:
  create     Create a new DID
  resolve    Resolve a DID
  update     Update an existing DID
  deactivate Deactivate an existing DID

Options:
  --domain [domain]         Domain for the DID (required for create)
  --log [file]              Path to the DID log file (required for resolve, update, deactivate)
  --output [file]           Path to save the updated DID log (optional for create, update, deactivate)
  --portable                Make the DID portable (optional for create)
  --prerotation             Enable pre-rotation (optional for create and update)
  --witness [witness]       Add a witness (can be used multiple times)
  --witness-threshold [n]   Set witness threshold (optional, defaults to number of witnesses)
  --service [service]       Add a service (format: type,endpoint) (can be used multiple times)
  --add-vm [type]           Add a verification method (type can be authentication, assertionMethod, keyAgreement, capabilityInvocation, capabilityDelegation)
  --also-known-as [alias]   Add an alsoKnownAs alias (can be used multiple times)
  --next-key-hash [hash]    Add a nextKeyHash (can be used multiple times)

Examples:
  bun run cli create --domain example.com --portable --witness did:example:witness1 --witness did:example:witness2
  bun run cli resolve --did did:tdw:123456:example.com
  bun run cli update --log ./did.jsonl --output ./updated-did.jsonl --add-vm keyAgreement --service LinkedDomains,https://example.com
  bun run cli deactivate --log ./did.jsonl --output ./deactivated-did.jsonl
`;

// Add this function at the top with the other constants
function showHelp() {
  console.log(usage);
}

// Export the handler functions for testing
export async function handleCreate(args: string[]) {
  const options = parseOptions(args);
  const domain = options['domain'] as string;
  const output = options['output'] as string | undefined;
  const portable = options['portable'] !== undefined;
  const prerotation = options['prerotation'] !== undefined;
  const witnesses = options['witness'] as string[] | undefined;
  const witnessThreshold = options['witness-threshold'] ? parseInt(options['witness-threshold'] as string) : witnesses?.length ?? 0;
  const nextKeyHashes = options['next-key-hash'] as string[] | undefined;

  if (!domain) {
    console.error('Domain is required for create command');
    process.exit(1);
  }

  if (prerotation && !nextKeyHashes) {
    console.error('next-key-hash is required when prerotation is enabled');
    process.exit(1);
  }

  try {
    // Create DID
    const authKey = await generateEd25519VerificationMethod();
    const { did, doc, meta, log } = await createDID({
      domain,
      signer: createSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      portable,
      prerotation,
      witnesses,
      witnessThreshold,
      nextKeyHashes,
    });

    console.log('Created DID:', did);

    if (output) {
      // Ensure output directory exists
      const outputDir = dirname(output);
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      // Write log to file
      writeLogToDisk(output, log);
      console.log(`DID log written to ${output}`);

      // Save verification method to env
      writeVerificationMethodToEnv({
        ...authKey, 
        controller: did, 
        id: `${did}#${authKey.publicKeyMultibase?.slice(-8)}`
      });
      console.log(`DID verification method saved to env`);

      // Write DID document for reference
      const docPath = output.replace('.jsonl', '.json');
      fs.writeFileSync(docPath, JSON.stringify(doc, null, 2).replace(/did:tdw:([^:]+)/g, 'did:web'));
      console.log(`DID WEB document written to ${docPath}`);
    } else {
      // If no output specified, print to console
      console.log('DID Document:', JSON.stringify(doc, null, 2));
      console.log('DID Log:', JSON.stringify(log, null, 2));
    }

    return { did, doc, meta, log };
  } catch (error) {
    console.error('Error creating DID:', error);
    process.exit(1);
  }
}

export async function handleResolve(args: string[]) {
  const options = parseOptions(args);
  const didIdentifier = options['did'] as string;
  const logFile = options['log'] as string;

  if (!didIdentifier && !logFile) {
    console.error('Either --did or --log is required for resolve command');
    process.exit(1);
  }

  try {
    let log: DIDLog;
    if (logFile) {
      log = readLogFromDisk(logFile);
    } else {
      log = await fetchLogFromIdentifier(didIdentifier);
    }

    const { did, doc, meta } = await resolveDIDFromLog(log);

    console.log('Resolved DID:', did);
    console.log('DID Document:', JSON.stringify(doc, null, 2));
    console.log('Metadata:', meta);

    return { did, doc, meta };
  } catch (error) {
    console.error('Error resolving DID:', error);
    process.exit(1);
  }
}

export async function handleUpdate(args: string[]) {
  const options = parseOptions(args);
  const logFile = options['log'] as string;
  const output = options['output'] as string | undefined;
  const prerotation = options['prerotation'] !== undefined;
  const witnesses = options['witness'] as string[] | undefined;
  const witnessThreshold = options['witness-threshold'] ? parseInt(options['witness-threshold'] as string) : undefined;
  const services = options['service'] ? parseServices(options['service'] as string[]) : undefined;
  const addVm = options['add-vm'] as string[] | undefined;
  const alsoKnownAs = options['also-known-as'] as string[] | undefined;
  const updateKey = options['update-key'] as string | undefined;

  if (!logFile) {
    console.error('Log file is required for update command');
    process.exit(1);
  }

  try {
    const log = readLogFromDisk(logFile);
    const { did, meta } = await resolveDIDFromLog(log);
    console.log('\nCurrent DID:', did);
    console.log('Current meta:', meta);
    
    // Get the verification method from environment
    const envVMs = JSON.parse(Buffer.from(process.env.DID_VERIFICATION_METHODS || 'W10=', 'base64').toString('utf8'));
    
    const vm = envVMs.find((vm: any) => vm.controller === did);
    console.log('\nFound VM:', vm);
    
    if (!vm) {
      throw new Error('No matching verification method found for DID');
    }

    // Only generate a new auth key if update-key wasn't provided
    const authKey = updateKey ? {
      type: "Multikey" as const,
      publicKeyMultibase: updateKey,
      secretKeyMultibase: vm.secretKeyMultibase,
      controller: did,
      id: `${did}#${updateKey.slice(-8)}`
    } : await generateEd25519VerificationMethod();
    
    console.log('\nNew auth key:', authKey);

    // Create verification methods array
    const verificationMethods: VerificationMethod[] = [];
    
    // If we're adding VMs, create a VM for each type
    if (addVm && addVm.length > 0) {
      const vmId = `${did}#${authKey.publicKeyMultibase!.slice(-8)}`;
      
      // Add a verification method for each type
      for (const vmType of addVm) {
        const newVM: VerificationMethod = {
          id: vmId,
          type: "Multikey",
          controller: did,
          publicKeyMultibase: authKey.publicKeyMultibase,
          secretKeyMultibase: authKey.secretKeyMultibase,
          purpose: vmType as VerificationMethodType
        };
        verificationMethods.push(newVM);
      }
    } else {
      // For non-VM updates (services, alsoKnownAs), still need a VM with purpose
      verificationMethods.push({
        id: `${did}#${authKey.publicKeyMultibase!.slice(-8)}`,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: authKey.publicKeyMultibase,
        secretKeyMultibase: authKey.secretKeyMultibase,
        purpose: "assertionMethod"
      });
    }

    const result = await updateDID({
      log,
      signer: createSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods,
      prerotation,
      witnesses,
      witnessThreshold,
      services,
      alsoKnownAs
    });

    if (output) {
      writeLogToDisk(output, result.log);
      console.log(`Updated DID log written to ${output}`);

      // Write DID document for reference
      const docPath = output.replace('.jsonl', '.json');
      fs.writeFileSync(docPath, JSON.stringify(result.doc, null, 2).replace(/did:tdw:([^:]+)/g, 'did:web'));
      console.log(`DID WEB document written to ${docPath}`);
    }

    return result;
  } catch (error) {
    console.error('Error updating DID:', error);
    process.exit(1);
  }
}

export async function handleDeactivate(args: string[]) {
  const options = parseOptions(args);
  const logFile = options['log'] as string;
  const output = options['output'] as string | undefined;

  if (!logFile) {
    console.error('Log file is required for deactivate command');
    process.exit(1);
  }

  try {
    // Read the current log to get the latest state
    const log = readLogFromDisk(logFile);
    const { did, meta } = await resolveDIDFromLog(log);
    console.log('Current DID:', did);
    console.log('Current meta:', meta);
    
    // Get the verification method from environment
    const envContent = fs.readFileSync('.env', 'utf8');
    const vmMatch = envContent.match(/DID_VERIFICATION_METHODS=(.+)/);
    if (!vmMatch) {
      throw new Error('No verification method found in .env file');
    }

    // Parse the VM from env
    const vm = JSON.parse(Buffer.from(vmMatch[1], 'base64').toString('utf8'))[0];
    if (!vm) {
      throw new Error('No verification method found in environment');
    }

    // Use the current authorized key from meta
    vm.publicKeyMultibase = meta.updateKeys[0];

    const result = await deactivateDID({
      log,
      signer: createSigner(vm)
    });

    if (output) {
      writeLogToDisk(output, result.log);
      console.log(`Deactivated DID log written to ${output}`);
    }

    return result;
  } catch (error) {
    console.error('Error deactivating DID:', error);
    process.exit(1);
  }
}

type VerificationMethodType = 'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation' | 'capabilityDelegation';

function parseOptions(args: string[]): Record<string, string | string[] | undefined> {
  const options: Record<string, string | string[] | undefined> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        if (key === 'witness' || key === 'service' || key === 'also-known-as' || key === 'next-key-hash') {
          options[key] = options[key] || [];
          (options[key] as string[]).push(args[++i]);
        } else if (key === 'add-vm') {
          options[key] = options[key] || [];
          const value = args[++i];
          if (isValidVerificationMethodType(value)) {
            (options[key] as VerificationMethodType[]).push(value);
          } else {
            console.error(`Invalid verification method type: ${value}`);
            process.exit(1);
          }
        } else {
          options[key] = args[++i];
        }
      } else {
        options[key] = '';
      }
    }
  }
  return options;
}

// Add this function to validate VerificationMethodType
function isValidVerificationMethodType(type: string): type is VerificationMethodType {
  return ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'].includes(type);
}

function parseServices(services: string[]): ServiceEndpoint[] {
  return services.map(service => {
    const [type, serviceEndpoint] = service.split(',');
    return { type, serviceEndpoint };
  });
}

// Update the main function to be exported
export async function main() {
  const [command, ...args] = process.argv.slice(2);
  console.log('Command:', command);
  console.log('Args:', args);

  try {
    switch (command) {
      case 'create':
        console.log('Handling create command...');
        await handleCreate(args);
        break;
      case 'resolve':
        await handleResolve(args);
        break;
      case 'update':
        await handleUpdate(args);
        break;
      case 'deactivate':
        await handleDeactivate(args);
        break;
      case 'help':
        showHelp();
        break;
      default:
        console.error('Unknown command:', command);
        showHelp();
        process.exit(1);
    }
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

// Only run main if this file is being executed directly
if (process.argv[1] === import.meta.path) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}
