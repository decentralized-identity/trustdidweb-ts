import { base58btc } from "multiformats/bases/base58";
import { canonicalize } from "json-canonicalize";
import { createHash } from "./crypto";
import { concatBuffers } from "./buffer";
import * as ed from '@noble/ed25519';
import type { VerificationMethod, DataIntegrityProof } from "../interfaces";

export async function createWitnessProof(
  witness: VerificationMethod,
  versionId: string
): Promise<DataIntegrityProof> {
  // Create the proof without value first
  const proof = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: `did:key:${witness.publicKeyMultibase}`,
    created: new Date().toISOString(),
    proofPurpose: "authentication"
  };

  // Hash the data and proof
  const dataHash = await createHash(canonicalize({versionId}));
  const proofHash = await createHash(canonicalize(proof));
  const input = concatBuffers(proofHash, dataHash);

  // Sign the input
  const secretKey = base58btc.decode(witness.secretKeyMultibase!).slice(2);
  const signature = await ed.signAsync(input, secretKey);
  
  // Return complete proof with signature
  return {
    ...proof,
    proofValue: base58btc.encode(signature)
  };
} 