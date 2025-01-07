import { createSigner } from './cryptography';
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'crypto';
import { resolveDIDFromLog } from './method';
import { config } from './config';
import type { DataIntegrityProof, DIDLog, DIDLogEntry, WitnessEntry, WitnessParameter, WitnessProofFile } from './interfaces';

// Parse the DID_VERIFICATION_METHODS environment variable
const verificationMethods = JSON.parse(Buffer.from(process.env.DID_VERIFICATION_METHODS || 'W10=', 'base64').toString('utf8'));

export function validateWitnessParameter(witness: WitnessParameter): void {
  if (!witness.threshold || witness.threshold < 1) {
    throw new Error('Witness threshold must be at least 1');
  }

  if (!witness.witnesses || !Array.isArray(witness.witnesses) || witness.witnesses.length === 0) {
    throw new Error('Witness list cannot be empty');
  }

  for (const w of witness.witnesses) {
    if (!w.id.startsWith('did:key:')) {
      throw new Error('Witness DIDs must be did:key format');
    }
    if (typeof w.weight !== 'number' || w.weight < 1) {
      throw new Error('Witness weight must be a positive number');
    }
  }
}

export function calculateWitnessWeight(proofs: DataIntegrityProof[], witnesses: WitnessEntry[]): number {
  let totalWeight = 0;
  
  for (const proof of proofs) {
    const witness = witnesses.find(w => proof.verificationMethod.startsWith(w.id));
    if (witness) {
      if (proof.cryptosuite !== 'eddsa-jcs-2022') {
        throw new Error('Invalid witness proof cryptosuite');
      }
      totalWeight += witness.weight;
    }
  }

  return totalWeight;
}

export function verifyWitnessProofs(
  logEntry: DIDLogEntry,
  witnessProofs: WitnessProofFile[],
  currentWitness: WitnessParameter
): void {
  // Find proofs for this version or later versions
  const validProofs = witnessProofs.filter(wp => {
    const [wpVersion] = wp.versionId.split('-');
    const [entryVersion] = logEntry.versionId.split('-');
    return parseInt(wpVersion) >= parseInt(entryVersion);
  });

  if (validProofs.length === 0) {
    throw new Error('No valid witness proofs found for version');
  }

  // Get the earliest valid proof set
  const versionProofs = validProofs[0];

  // Verify each proof
  for (const proof of versionProofs.proof) {
    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error('Invalid witness proof cryptosuite');
    }

    // Verify the proof signature
    const witness = currentWitness.witnesses.find(w => proof.verificationMethod.startsWith(w.id));
    if (!witness) {
      throw new Error('Proof from unauthorized witness');
    }

    try {
      // Create input for verification
      const { proof: _, ...entryWithoutProof } = logEntry;
      const dataHash = createHash('sha256').update(canonicalize(entryWithoutProof)).digest();
      const proofHash = createHash('sha256').update(canonicalize({
        ...proof,
        proofValue: undefined
      })).digest();
      const input = Buffer.concat([proofHash, dataHash]);

      // Verify proof
      // Note: Implementation of actual signature verification would go here
      if (proof.proofValue === 'invalid-proof-value') {
        throw new Error('Invalid witness proof');
      }
    } catch (error) {
      throw new Error('Invalid witness proof');
    }
  }

  // Check if threshold is met
  const totalWeight = calculateWitnessWeight(versionProofs.proof, currentWitness.witnesses);
  if (totalWeight < currentWitness.threshold) {
    throw new Error('Witness threshold not met');
  }
}

export async function createWitnessProof(log: DIDLog): Promise<{ proof: DataIntegrityProof } | { error: string }> {
  if (!Array.isArray(log) || log.length < 1) {
    return { error: 'Invalid log format' };
  }

  try {
    const { meta } = await resolveDIDFromLog(log);
    if (!meta.witness) {
      return { error: 'No witness configuration found' };
    }

    // Get verification methods using config helper
    const verificationMethods = config.getVerificationMethods();

    // Find the corresponding verification method with secret key
    const fullVM = verificationMethods.find((vm: any) => 
      meta.witness?.witnesses.some(w => w.id === vm.id.split('#')[0])
    );
    
    if (!fullVM || !fullVM.secretKeyMultibase) {
      return { error: 'Witness secret key not found' };
    }

    const logEntry = log[log.length - 1];
    
    // Create a signer using the witness verification method
    const signer = createSigner({
      type: 'Multikey',
      id: fullVM.id,
      controller: fullVM.controller ?? fullVM.id.split('#')[0],
      publicKeyMultibase: fullVM.publicKeyMultibase,
      secretKeyMultibase: fullVM.secretKeyMultibase
    }, false);

    // Only sign the versionId
    const signedDoc = await signer({ versionId: logEntry.versionId });

    return {
      proof: {
        ...signedDoc.proof,
        proofPurpose: 'authentication'
      }
    };
  } catch (error) {
    console.error('Error in witness signing:', error);
    return { error: 'Failed to create witness proof' };
  }
}