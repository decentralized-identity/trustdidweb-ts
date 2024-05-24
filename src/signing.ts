import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import * as ed from '@noble/ed25519';
import { bytesToHex, createDate } from "./utils";
import { base58btc } from "multiformats/bases/base58"
import { canonicalize } from 'json-canonicalize';
import { createHash } from 'node:crypto';

export const signDocument = async (doc: any, vm: VerificationMethod, challenge: string) => {
  try {
    // const keyPair = await Ed25519Multikey.from({
    //   '@context': 'https://w3id.org/security/multikey/v1',
    //   type: 'Multikey',
    //   controller: doc.id,
    //   id: vm.id,
    //   publicKeyMultibase: vm.publicKeyMultibase,
    //   secretKeyMultibase: vm.secretKeyMultibase
    // });
    // const suite = new DataIntegrityProof({
    //   signer: keyPair.signer(), cryptosuite: eddsa2022CryptoSuite
    // });
    const proof: any = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: vm.id,
      created: createDate(),
      proofPurpose: 'authentication',
      challenge
    }
    const dataHash = createHash('sha256').update(canonicalize(doc)).digest();
    const proofHash = createHash('sha256').update(canonicalize(proof)).digest();
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