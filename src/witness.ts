import { canonicalize } from 'json-canonicalize';
import { createHash } from './utils/crypto';
import type { DataIntegrityProof, DIDLogEntry, WitnessEntry, WitnessParameter, WitnessProofFileEntry } from './interfaces';
import * as ed from '@noble/ed25519';
import { base58btc } from "multiformats/bases/base58";
import { resolveVM } from "./utils";
import { bufferToString, concatBuffers } from './utils/buffer';


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

export async function verifyWitnessProofs(
  logEntry: DIDLogEntry,
  witnessProofs: WitnessProofFileEntry[],
  currentWitness: WitnessParameter
): Promise<void> {
  const validProofs = witnessProofs.filter(wp => wp.versionId === logEntry.versionId);
  
  if (validProofs.length === 0) {
    throw new Error('No valid witness proofs found for version');
  }

  let totalWeight = 0;
  const processedWitnesses = new Set<string>();

  for (const proofSet of validProofs) {
    for (const proof of proofSet.proof) {
      if (proof.cryptosuite !== 'eddsa-jcs-2022') {
        throw new Error('Invalid witness proof cryptosuite');
      }

      const witness = currentWitness.witnesses.find(w => proof.verificationMethod.startsWith(w.id));
      if (!witness) {
        throw new Error('Proof from unauthorized witness');
      }

      if (processedWitnesses.has(witness.id)) {
        continue;
      }

      try {
        const vm = await resolveVM(proof.verificationMethod);
        if (!vm) {
          throw new Error(`Verification Method ${proof.verificationMethod} not found`);
        }

        const publicKey = base58btc.decode(vm.publicKeyMultibase!);
        if (publicKey[0] !== 0xed || publicKey[1] !== 0x01) {
          throw new Error(`multiKey doesn't include ed25519 header (0xed01)`);
        }

        const { proofValue, ...proofWithoutValue } = proof;
        const dataHash = await createHash(canonicalize({versionId: logEntry.versionId}));
        const proofHash = await createHash(canonicalize(proofWithoutValue));
        const input = concatBuffers(proofHash, dataHash);

        const signature = base58btc.decode(proofValue);
        const signatureHex = bufferToString(signature, 'hex');
        const inputHex = bufferToString(input, 'hex');
        const publicKeyHex = bufferToString(publicKey.slice(2), 'hex');

        const verified = await ed.verifyAsync(
          signatureHex,
          inputHex,
          publicKeyHex
        );

        if (!verified) {
          throw new Error('Invalid witness proof signature');
        }

        totalWeight += witness.weight;
        processedWitnesses.add(witness.id);

      } catch (error: any) {
        throw new Error(`Invalid witness proof: ${error.message}`);
      }
    }
  }

  if (totalWeight < currentWitness.threshold) {
    throw new Error(`Witness threshold not met: got ${totalWeight}, need ${currentWitness.threshold}`);
  }
}