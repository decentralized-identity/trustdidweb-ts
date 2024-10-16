import * as ed from '@noble/ed25519';
import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';

import { bytesToHex, createDate } from "./utils";
import { base58btc } from "multiformats/bases/base58"
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'node:crypto';

export const createSigner = (vm: VerificationMethod, useStatic: boolean = true) => {
  return async (doc: any, challenge: string) => {
    try {
      const proof: any = {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: useStatic ? `did:key:${vm.publicKeyMultibase}` : vm.id,
        created: createDate(),
        proofPurpose: 'authentication',
        challenge
      }
      const dataHash = createHash('sha256').update(canonicalize(doc)).digest();
      const proofHash = createHash('sha256').update(canonicalize(proof)).digest();
      const input = Buffer.concat([proofHash, dataHash]);
      const secretKey = base58btc.decode(vm.secretKeyMultibase!).slice(2);

      const signature = await ed.signAsync(Buffer.from(input).toString('hex'), Buffer.from(secretKey).toString('hex'));

      proof.proofValue = base58btc.encode(signature);
      return {...doc, proof};
    } catch (e: any) {
      console.error(e)
      throw new Error(`Document signing failure: ${e.message || e}`)
    }
  }
}

export const generateEd25519VerificationMethod = async (): Promise<VerificationMethod> => {
  const privKey = ed.utils.randomPrivateKey();
  const pubKey = await ed.getPublicKeyAsync(privKey);
  const publicKeyMultibase = base58btc.encode(Buffer.concat([new Uint8Array([0xed, 0x01]), pubKey]));
  const secretKeyMultibase = base58btc.encode(Buffer.concat([new Uint8Array([0x80, 0x26]), privKey]));

  return {
    type: "Multikey",
    publicKeyMultibase,
    secretKeyMultibase,
    purpose: 'authentication'
  };
}

export const generateX25519VerificationMethod = async (): Promise<VerificationMethod> => {
  const privKey = ed.utils.randomPrivateKey();
  const pubKey = await ed.getPublicKeyAsync(privKey);
  const x25519PubKey = edwardsToMontgomeryPub(pubKey);
  const x25519PrivKey = edwardsToMontgomeryPriv(privKey);
  const publicKeyMultibase = base58btc.encode(Buffer.concat([new Uint8Array([0xec, 0x01]), x25519PubKey]));
  const secretKeyMultibase = base58btc.encode(Buffer.concat([new Uint8Array([0x82, 0x26]), x25519PrivKey]));

  return {
    type: "Multikey",
    publicKeyMultibase,
    secretKeyMultibase,
    purpose: 'keyAgreement'
  }
}
