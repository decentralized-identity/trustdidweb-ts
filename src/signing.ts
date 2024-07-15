import * as ed from '@noble/ed25519';
import { bytesToHex, createDate } from "./utils";
import { base58btc } from "multiformats/bases/base58"
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'node:crypto';

export const createSigner = (vm: VerificationMethod) => {
  return async (doc: any, challenge: string) => {
    try {
      const proof: any = {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: `did:key:${vm.publicKeyMultibase}`,
        created: createDate(),
        proofPurpose: 'authentication',
        challenge
      }
      const dataHash = createHash('sha3-256').update(canonicalize(doc)).digest();
      const proofHash = createHash('sha3-256').update(canonicalize(proof)).digest();
      const input = Buffer.concat([dataHash, proofHash]);
      const secretKey = base58btc.decode(vm.secretKeyMultibase!);

      const output = await ed.signAsync(bytesToHex(input), bytesToHex(secretKey.slice(2, 34)));

      proof.proofValue = base58btc.encode(output);
      return {...doc, proof};
    } catch (e: any) {
      console.error(e)
      throw new Error(`Document signing failure: ${e.details}`)
    }
  }
}
