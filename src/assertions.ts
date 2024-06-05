import * as ed from '@noble/ed25519';
import { base58btc } from "multiformats/bases/base58";
import { bytesToHex } from "./utils";
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'node:crypto';

export const keyIsAuthorized = (verificationMethod: string, updateKeys: string[]) => {
  return updateKeys.includes(verificationMethod);
}

export const documentStateIsValid = async (doc: any, proofs: any[], updateKeys: string[]) => {
  let i = 0;
  while(i < proofs.length) {
    const proof = proofs[i];
    if (!keyIsAuthorized(proof.verificationMethod.split('#')[0], updateKeys)) {
      throw new Error(`key ${proof.verificationMethod} is not authorized to update.`)
    }
    if (proof.type !== 'DataIntegrityProof') {
      throw new Error(`Unknown proof type ${proof.type}`);
    }
    if (proof.proofPurpose !== 'authentication') {
      throw new Error(`Unknown proof purpose] ${proof.proofPurpose}`);
    }
    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error(`Unknown cryptosuite ${proof.cryptosuite}`);
    }
    const publicKey = base58btc.decode(proof.verificationMethod.split('did:key:')[1].split('#')[0]);
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

export const newKeysAreValid = (options: CreateDIDInterface | UpdateDIDInterface) => {
  if(!options.verificationMethods?.find(vm => vm.type === 'authentication')) {
    throw new Error("DIDDoc MUST contain at least one authentication key type");
  }
  if(options.prerotate) {}
}