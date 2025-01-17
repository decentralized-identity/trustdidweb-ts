import { beforeAll, describe, expect, test } from "bun:test";
import { createDID, resolveDIDFromLog, updateDID } from "../src/method";
import { createSigner, generateEd25519VerificationMethod } from "../src/cryptography";
import { DIDLog, VerificationMethod } from "../src/interfaces";
import { createWitnessProof } from "../src/utils/witness";

describe("Witness Implementation Tests", async () => {

  let authKey: VerificationMethod;
  let witness1: VerificationMethod, witness2: VerificationMethod, witness3: VerificationMethod;
  let initialDID: { did: string; doc: any; meta: any; log: DIDLog };

  beforeAll(async () => {
    authKey = await generateEd25519VerificationMethod();
    witness1 = await generateEd25519VerificationMethod();
    witness2 = await generateEd25519VerificationMethod();
    witness3 = await generateEd25519VerificationMethod();
  });

  test("Create DID with weighted witness threshold", async () => {
    initialDID = await createDID({
      domain: 'example.com',
      signer: createSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      witness: {
        threshold: 3,
        witnesses: [
          { id: `did:key:${witness1.publicKeyMultibase}`, weight: 2 },
          { id: `did:key:${witness2.publicKeyMultibase}`, weight: 1 },
          { id: `did:key:${witness3.publicKeyMultibase}`, weight: 1 }
        ]
      }
    });

    expect(initialDID.meta.witness.threshold).toBe(3);
    expect(initialDID.meta.witness.witnesses).toHaveLength(3);
    expect(initialDID.meta.witness.witnesses[0].weight).toBe(2);
  });

  test("Update DID with witness proofs meeting threshold", async () => {
    const newAuthKey = await generateEd25519VerificationMethod();
    
    // Create witness proofs
    const versionId = initialDID.log[0].versionId;
    
    // Create proofs from witness1 and witness2
    const proofs = await Promise.all([
      witness1, 
      witness2
    ].map(witness => createWitnessProof(witness, versionId)));

    const witnessProofs = [{
      versionId,
      proof: proofs
    }];

    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createSigner(authKey),
      updateKeys: [newAuthKey.publicKeyMultibase!],
      verificationMethods: [newAuthKey],
      witnessProofs
    });

    expect(updatedDID.meta?.witness?.threshold).toBe(3);
  });

  test("Replace witness list with new witnesses", async () => {
    const newWitness = await generateEd25519VerificationMethod();
    
    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      witness: {
        threshold: 1,
        witnesses: [
          { id: `did:key:${newWitness.publicKeyMultibase}`, weight: 1 }
        ]
      }
    });

    expect(updatedDID.meta?.witness?.witnesses).toHaveLength(1);
    expect(updatedDID.meta?.witness?.threshold).toBe(1);
  });

  test("Disable witnessing by setting witness list to null", async () => {
    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      witness: null
    });

    expect(updatedDID.meta.witness).toBeNull();
  });

  test("Verify witness proofs from did-witness.json", async () => {
    // Create real witness proofs using the utility
    const mockWitnessFile = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(witness1, initialDID.log[0].versionId)
        ]
      },
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(witness2, initialDID.log[0].versionId)
        ]
      },
      {
        versionId: "future-version-id",
        proof: [
          // This proof should be ignored since version doesn't exist in log
          await createWitnessProof(witness1, "future-version-id")
        ]
      }
    ];

    const resolved = await resolveDIDFromLog(initialDID.log, {
      witnessProofs: mockWitnessFile
    });

    expect(resolved.did).toBe(initialDID.did);
  });
});
