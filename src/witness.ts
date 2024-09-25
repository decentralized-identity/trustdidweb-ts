import { createSigner } from './cryptography';

// Parse the DID_VERIFICATION_METHODS environment variable
const verificationMethods = JSON.parse(Buffer.from(process.env.DID_VERIFICATION_METHODS || '', 'base64').toString('utf8'));

export async function createWitnessProof(log: DIDLog): Promise<{ proof: any } | { error: string }> {
  if (!Array.isArray(log)) {
    return { error: 'Invalid log format' };
  }

  // Find the first verification method with type 'authentication'
  const authVM = verificationMethods.find((vm: any) => vm.type === 'authentication');

  if (!authVM) {
    return { error: 'No authentication verification method found' };
  }

  try {
    const logEntry = log[log.length - 1];
    const [versionId, timestamp, params, data] = logEntry;

    // Create a signer using the authentication verification method
    const signer = createSigner({
      type: authVM.type,
      publicKeyMultibase: authVM.publicKeyMultibase,
      secretKeyMultibase: authVM.secretKeyMultibase
    });

    // Sign the log entry
    const signedDoc = await signer(
      { versionId, timestamp, params, data },
      versionId
    );

    return {
      proof: signedDoc.proof
    };
  } catch (error) {
    console.error('Error in witness signing:', error);
    return { error: 'Failed to create witness proof' };
  }
}