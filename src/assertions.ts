import * as ed from '@noble/ed25519';
import { base58btc } from "multiformats/bases/base58";
import { bytesToHex, createSCID, deriveHash, deriveNextKeyHash, resolveVM } from "./utils";
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'node:crypto';

const isKeyAuthorized = (verificationMethod: string, updateKeys: string[]): boolean => {
  if (process.env.IGNORE_ASSERTION_KEY_IS_AUTHORIZED) return true;

  if (verificationMethod.startsWith('did:key:')) {
    const key = verificationMethod.split('did:key:')[1].split('#')[0];
    return updateKeys.includes(key);
  }
  return false;
};

const isWitnessAuthorized = (verificationMethod: string, witnesses: string[]): boolean => {
  if (process.env.IGNORE_WITNESS_IS_AUTHORIZED) return true;

  if (verificationMethod.startsWith('did:tdw:')) {
    const didWithoutFragment = verificationMethod.split('#')[0];
    return witnesses.includes(didWithoutFragment);
  }
  return false;
};

export const documentStateIsValid = async (doc: any, updateKeys: string[], witnesses: string[] = []) => {
  if (process.env.IGNORE_ASSERTION_DOCUMENT_STATE_IS_VALID) return true;
  const {proof: proofs, ...rest} = doc;
  for (let i = 0; i < proofs.length; i++) {
    const proof = proofs[i];

    if (proof.verificationMethod.startsWith('did:key:')) {
      if (!isKeyAuthorized(proof.verificationMethod, updateKeys)) {
        throw new Error(`Key ${proof.verificationMethod} is not authorized to update.`);
      }
    } else if (proof.verificationMethod.startsWith('did:tdw:')) {
      if (witnesses.length > 0 && !isWitnessAuthorized(proof.verificationMethod, witnesses)) {
        throw new Error(`Key ${proof.verificationMethod} is not from an authorized witness.`);
      }
    } else {
      throw new Error(`Unsupported verification method: ${proof.verificationMethod}`);
    }
    
    if (proof.type !== 'DataIntegrityProof') {
      throw new Error(`Unknown proof type ${proof.type}`);
    }
    if (proof.proofPurpose !== 'authentication' && proof.proofPurpose !== 'assertionMethod') {
      throw new Error(`Unknown proof purpose ${proof.proofPurpose}`);
    }
    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error(`Unknown cryptosuite ${proof.cryptosuite}`);
    }

    const vm = await resolveVM(proof.verificationMethod);
    if (!vm) {
      throw new Error(`Verification Method ${proof.verificationMethod} not found`);
    }

    const publicKey = base58btc.decode(vm.publicKeyMultibase!);
    if (publicKey[0] !== 0xed || publicKey[1] !== 0x01) {
      throw new Error(`multiKey doesn't include ed25519 header (0xed01)`);
    }

    const {proofValue, ...restProof} = proof;
    const signature = base58btc.decode(proofValue);
    const dataHash = createHash('sha256').update(canonicalize(rest)).digest();
    const proofHash = createHash('sha256').update(canonicalize(restProof)).digest();
    const input = Buffer.concat([proofHash, dataHash]);

    const verified = await ed.verifyAsync(Buffer.from(signature).toString('hex'), Buffer.from(input).toString('hex'), Buffer.from(publicKey.slice(2)).toString('hex'));
    if (!verified) {
      throw new Error(`Proof ${i} failed verification`);
    }
  }
  return true;
}

export const hashChainValid = (derivedHash: string, logEntryHash: string) => {
  if (process.env.IGNORE_ASSERTION_HASH_CHAIN_IS_VALID) return true;
  return derivedHash === logEntryHash;
}

export const newKeysAreValid = (updateKeys: string[], previousNextKeyHashes: string[], nextKeyHashes: string[], previousPrerotation: boolean, prerotation: boolean) => {
  if (process.env.IGNORE_ASSERTION_NEW_KEYS_ARE_VALID) return true;
  if (prerotation && nextKeyHashes.length === 0) {
    throw new Error(`nextKeyHashes are required if prerotation enabled`);
  }
  if(previousPrerotation) {
    const inNextKeyHashes = updateKeys.reduce((result, key) => {
      const hashedKey = deriveNextKeyHash(key);
      return result && previousNextKeyHashes.includes(hashedKey);
    }, true);
    if (!inNextKeyHashes) {
      throw new Error(`invalid updateKeys ${updateKeys}`);
    }
  }
  return true;
}

export const scidIsFromHash = async (scid: string, hash: string) => {
  if (process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH) return true;
  return scid === await createSCID(hash);
}
