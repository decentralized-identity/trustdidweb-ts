import { beforeAll, describe, expect, test } from "bun:test";
import { createDID, deactivateDID, resolveDIDFromLog, updateDID } from "../src/method";
import { createSigner, generateEd25519VerificationMethod } from "../src/cryptography";
import { isWitnessServerRunning } from "./utils";
import type { DIDLog, VerificationMethod } from "../src/interfaces";

describe("did:webvh normative tests", async () => {
  let newDoc1: any;
  let newLog1: DIDLog;
  let authKey1: VerificationMethod;

  beforeAll(async () => {
    authKey1 = await generateEd25519VerificationMethod();

    const { doc, log } = await createDID({
      domain: 'example.com',
      signer: createSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: [authKey1],
      created: new Date('2024-01-01T08:32:55Z')
    });

    newDoc1 = doc;
    newLog1 = log;
  });

  test("Resolve MUST process the DID Log correctly (positive)", async () => {
    const resolved = await resolveDIDFromLog(newLog1);
    expect(resolved.meta.versionId.split('-')[0]).toBe("1");
  });

  test("Resolve MUST process the DID Log correctly (negative)", async () => {
    let err;
    const malformedLog = "malformed log content";
    try {
      await resolveDIDFromLog(malformedLog as any);
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
  });

  test("Update implementation MUST generate a correct DID Entry (positive)", async () => {
    const authKey2 = await generateEd25519VerificationMethod();
    const { doc: updatedDoc, log: updatedLog } = await updateDID({
      log: newLog1,
      signer: createSigner(authKey2),
      updateKeys: [authKey2.publicKeyMultibase!],
      context: newDoc1['@context'],
      verificationMethods: [authKey2],
      updated: new Date('2024-02-01T08:32:55Z')
    });

    expect(updatedLog[1].versionId).toBeDefined();
    expect(updatedLog[1].versionId.split('-')[0]).toBe("2");
  });

  test("Resolver encountering 'deactivated': true MUST return deactivated in metadata (positive)", async () => {
    const { log: updatedLog } = await deactivateDID({
      log: newLog1,
      signer: createSigner(authKey1)
    });
    const resolved = await resolveDIDFromLog(updatedLog);
    expect(resolved.meta.deactivated).toBe(true);
  });

  test("Resolver encountering 'deactivated': false MUST return deactivated in metadata (negative)", async () => {
    const resolved = await resolveDIDFromLog(newLog1);
    expect(resolved.meta.deactivated).toBeFalse();
  });
});

describe("did:webvh normative witness tests", async () => {
  const WITNESS_SERVER_URL = "http://localhost:8000";
  const serverRunning = await isWitnessServerRunning(WITNESS_SERVER_URL);
  console.log("serverRunning", serverRunning);
  if (!serverRunning) {
    describe("Witness functionality", () => {
      test.skip("Witness server is not running", () => {});
    });
    return;
  }

  let authKey1: VerificationMethod;
  let witness1DID: string, witness2DID: string, witness3DID: string;
  let initialDID: { did: string; doc: any; meta: any; log: DIDLog };

  beforeAll(async () => {
    authKey1 = await generateEd25519VerificationMethod();
    // Create witness DIDs (should be did:key format)
    witness1DID = "did:key:z6MkrBXGwmSFjaqxQeqMMXU6BWwrgPW2BkFXv15HSJ4UijKX";
    witness2DID = "did:key:z6MkrBXGwmSFjaqxQeqMMXU6BWwrgPW2BkFXv15HSJ4UijKY";
    witness3DID = "did:key:z6MkrBXGwmSFjaqxQeqMMXU6BWwrgPW2BkFXv15HSJ4UijKZ";
  });

  test("witness parameter MUST use did:key DIDs", async () => {
    let err;
    try {
      await createDID({
        domain: 'example.com',
        signer: createSigner(authKey1),
        updateKeys: [authKey1.publicKeyMultibase!],
        verificationMethods: [authKey1],
        witness: {
          threshold: 2,
          witnesses: [
            { id: "did:web:example.com", weight: 1 }, // Invalid - not did:key
            { id: witness1DID, weight: 1 }
          ]
        }
      });
    } catch (e: any) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err.message).toContain("Witness DIDs must be did:key format");
  });

  test("witness threshold MUST be met for DID updates", async () => {
    // First create a DID with witnesses
    initialDID = await createDID({
      domain: 'example.com',
      signer: createSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: [authKey1],
      witness: {
        threshold: 2,
        witnesses: [
          { id: witness1DID, weight: 1 },
          { id: witness2DID, weight: 1 },
          { id: witness3DID, weight: 1 }
        ]
      }
    });

    // Mock witness proofs file
    const mockWitnessProofs = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          // Only one witness proof - should fail threshold
          {
            type: "DataIntegrityProof",
            cryptosuite: "eddsa-jcs-2022",
            verificationMethod: witness1DID,
            proofValue: "z58xkL6dbDRJjFVkBxhNHXNHFnZzZk..."
          }
        ]
      }
    ];

    let err;
    try {
      await resolveDIDFromLog(initialDID.log, { witnessProofs: mockWitnessProofs as any });
    } catch (e: any) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err.message).toContain("Witness threshold not met");
  });

  test("witness proofs MUST use eddsa-jcs-2022 cryptosuite", async () => {
    const mockWitnessProofs = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          {
            type: "DataIntegrityProof",
            cryptosuite: "invalid-suite", // Invalid cryptosuite
            verificationMethod: witness1DID,
            proofValue: "z58xkL6dbDRJjFVkBxhNHXNHFnZzZk..."
          }
        ]
      }
    ];

    let err;
    try {
      await resolveDIDFromLog(initialDID.log, { witnessProofs: mockWitnessProofs as any });
    } catch (e: any) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err.message).toContain("Invalid witness proof cryptosuite");
  });

  test("resolver MUST verify witness proofs before accepting DID update", async () => {
    const mockWitnessProofs = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          {
            type: "DataIntegrityProof",
            cryptosuite: "eddsa-jcs-2022",
            verificationMethod: witness1DID,
            proofValue: "invalid-proof-value" // Invalid proof value
          }
        ]
      }
    ];

    let err;
    try {
      await resolveDIDFromLog(initialDID.log, { witnessProofs: mockWitnessProofs as any });
    } catch (e: any) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err.message).toContain("Invalid witness proof");
  });
});
