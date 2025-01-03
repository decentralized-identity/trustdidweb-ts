import { createSigner } from './cryptography';
import { resolveDIDFromLog } from './method';
import { config } from './config';
import type { DIDLog } from './interfaces';

export async function createWitnessProof(log: DIDLog): Promise<{ proof: any } | { error: string }> {
  if (!Array.isArray(log) || log.length < 1) {
    return { error: 'Invalid log format' };
  }

  try {
    const { did, doc, meta } = await resolveDIDFromLog(log);

    // Get verification methods using config helper
    const verificationMethods = config.getVerificationMethods();

    // Find the corresponding verification method with secret key
    const fullVM = verificationMethods.find((vm: any) => meta.witnesses.includes(vm.id.split('#')[0]));
    if (!fullVM || !fullVM.secretKeyMultibase) {
      return { error: 'Witness secret key not found' };
    }

    const logEntry = log[log.length - 1];
    const { versionId, versionTime, parameters, state } = logEntry;

    // Create a signer using the witness verification method
    const signer = createSigner({
      type: 'Multikey',
      id: fullVM.id,
      controller: fullVM.controller ?? fullVM.id.split('#')[0],
      publicKeyMultibase: fullVM.publicKeyMultibase,
      secretKeyMultibase: fullVM.secretKeyMultibase
    }, false);
    const {proof, ...entry} = logEntry;
    const signedDoc = await signer(entry);

    return {
      proof: signedDoc.proof
    };
  } catch (error) {
    console.error('Error in witness signing:', error);
    return { error: 'Failed to create witness proof' };
  }
}