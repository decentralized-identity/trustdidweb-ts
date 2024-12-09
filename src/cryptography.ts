import * as ed from '@noble/ed25519';
import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import { createDate } from "./utils";
import { base58btc } from "multiformats/bases/base58"
import { canonicalize } from 'json-canonicalize';
import { createHash } from './utils/crypto';
import type { VerificationMethod } from './interfaces';
import { hexToBytes } from '@noble/curves/abstract/utils';
import { bufferToString, concatBuffers } from './utils/buffer';

export const createSigner = (vm: VerificationMethod, useStatic: boolean = true) => {
  return async (doc: any) => {
    try {
      const proof: any = {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: useStatic ? `did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}` : vm.id,
        created: createDate(),
        proofPurpose: 'assertionMethod'       
      }
      const dataHash = await createHash(canonicalize(doc));
      const proofHash = await createHash(canonicalize(proof));
      const input = concatBuffers(proofHash, dataHash);
      const secretKey = base58btc.decode(vm.secretKeyMultibase!).slice(2);
      
      // Convert input and secretKey to hex strings for ed25519 signing
      const inputHex = bufferToString(input, 'hex');
      const secretKeyHex = bufferToString(secretKey, 'hex');
      
      const signature = await ed.signAsync(inputHex, secretKeyHex);

      proof.proofValue = base58btc.encode(signature);
      return {...doc, proof};
    } catch (e: any) {
      console.error(e)
      throw new Error(`Document signing failure: ${e.message || e}`)
    }
  }
}

export async function generateEd25519VerificationMethod(): Promise<VerificationMethod> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  
  return {
    type: 'Multikey',
    publicKeyMultibase: base58btc.encode(new Uint8Array([0xed, 0x01, ...publicKey])),
    secretKeyMultibase: base58btc.encode(new Uint8Array([0xed, 0x01, ...privateKey])),
    purpose: 'assertionMethod'
  };
}

export async function generateX25519VerificationMethod(): Promise<VerificationMethod> {
  const edPrivateKey = ed.utils.randomPrivateKey();
  const edPublicKey = await ed.getPublicKeyAsync(edPrivateKey);
  
  // Convert Uint8Arrays to hex strings for curve conversion
  const pubHex = bufferToString(edPublicKey, 'hex');
  const privHex = bufferToString(edPrivateKey, 'hex');
  
  const publicKey = edwardsToMontgomeryPub(hexToBytes(pubHex));
  const privateKey = edwardsToMontgomeryPriv(hexToBytes(privHex));
  
  return {
    type: 'Multikey',
    purpose: 'keyAgreement',
    publicKeyMultibase: base58btc.encode(new Uint8Array([0xec, 0x01, ...publicKey])),
    secretKeyMultibase: base58btc.encode(new Uint8Array([0xec, 0x01, ...privateKey]))
  };
}
