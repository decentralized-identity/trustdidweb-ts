import * as ed from '@noble/ed25519';
import { base58btc } from "multiformats/bases/base58";
import { bytesToHex } from "./utils";
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'node:crypto';

export const isKeyAuthorized = (authKey: VerificationMethod, prevDoc: any) => {
  return prevDoc.authentication.some((kId: string) => kId === authKey.id);
}


export const isDocumentStateValid = async (authKey: VerificationMethod, doc: any, proofs: any[], prevDoc: any) => {
  if (!isKeyAuthorized(authKey, prevDoc)) {
    throw new Error(`key ${authKey.id} is not authorized to update.`)
  }
  let i = 0;
  while(i < proofs.length) {
    const proof = proofs[i];
    if (proof.type !== 'DataIntegrityProof') {
      throw new Error(`Unknown proof type ${proof.type}`);
    }
    if (proof.proofPurpose !== 'authentication') {
      throw new Error(`Unknown proof purpose] ${proof.proofPurpose}`);
    }
    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error(`Unknown cryptosuite ${proof.cryptosuite}`);
    }
    const publicKey = base58btc.decode(authKey.publicKeyMultibase!);
    const {proofValue, ...restProof} = proof;
    const sig = base58btc.decode(proofValue);
    const dataHash = createHash('sha256').update(canonicalize(doc)).digest();
    const proofHash = createHash('sha256').update(canonicalize(restProof)).digest();
    const input = Buffer.concat([dataHash, proofHash]);

    const verified = await ed.verifyAsync(
      bytesToHex(sig),
      bytesToHex(input),
      bytesToHex(publicKey.slice(2))
    );
    if (!verified) {
      return false;
    }
    i++;
  }
  return true;
}
