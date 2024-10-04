import { describe, expect, test, beforeAll } from "bun:test";
import { createDID, resolveDID, updateDID } from "../src/method";
import { createSigner, generateEd25519VerificationMethod, generateX25519VerificationMethod } from "../src/cryptography";
import { clone } from "../src/utils";

describe("resolveDID with verificationMethod", () => {
  let initialDID: string;
  let fullLog: DIDLog;
  let authKey1: VerificationMethod, authKey2: VerificationMethod, keyAgreementKey: VerificationMethod;

  beforeAll(async () => {
    authKey1 = await generateEd25519VerificationMethod('authentication');
    authKey2 = await generateEd25519VerificationMethod('authentication');
    keyAgreementKey = await generateX25519VerificationMethod('keyAgreement');

    // Create initial DID
    const { did, log } = await createDID({
      domain: 'example.com',
      signer: createSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: [authKey1],
      created: new Date('2023-01-01T00:00:00Z')
    });
    initialDID = did;
    fullLog = clone(log);

    // Update DID to add a new authentication key
    const updateResult1 = await updateDID({
      log: fullLog,
      signer: createSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: [authKey1, authKey2],
      updated: new Date('2023-02-01T00:00:00Z')
    });
    fullLog = updateResult1.log;

    // Update DID to add a keyAgreement key
    const updateResult2 = await updateDID({
      log: fullLog,
      signer: createSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: [authKey1, authKey2, keyAgreementKey],
      updated: new Date('2023-03-01T00:00:00Z')
    });
    fullLog = updateResult2.log;
  });

  test("Resolve DID with initial authentication key", async () => {
    const vmId = `${initialDID}#${authKey1.publicKeyMultibase!.slice(-8)}`;
    const { doc, meta } = await resolveDID(fullLog, { verificationMethod: vmId });
    
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.verificationMethod[0].publicKeyMultibase).toBe(authKey1.publicKeyMultibase);
    expect(meta.versionId.split('-')[0]).toBe("1");
  });

  test("Resolve DID with second authentication key", async () => {
    const vmId = `${initialDID}#${authKey2.publicKeyMultibase!.slice(-8)}`;
    const { doc, meta } = await resolveDID(fullLog, { verificationMethod: vmId });
    
    expect(doc.verificationMethod).toHaveLength(2);
    expect(doc.verificationMethod[1].publicKeyMultibase).toBe(authKey2.publicKeyMultibase);
    expect(meta.versionId.split('-')[0]).toBe("2");
  });

  test("Resolve DID with keyAgreement key", async () => {
    const vmId = `${initialDID}#${keyAgreementKey.publicKeyMultibase!.slice(-8)}`;
    const { doc, meta } = await resolveDID(fullLog, { verificationMethod: vmId });
    
    expect(doc.verificationMethod).toHaveLength(3);
    expect(doc.verificationMethod[2].publicKeyMultibase).toBe(keyAgreementKey.publicKeyMultibase);
    expect(meta.versionId.split('-')[0]).toBe("3");
  });

  test("Resolve DID with non-existent verification method", async () => {
    const vmId = `${initialDID}#nonexistent`;
    await expect(resolveDID(fullLog, { verificationMethod: vmId })).rejects.toThrow("DID with options");
  });

  test("Resolve DID with verification method and version time", async () => {
    const vmId = `${initialDID}#${authKey2.publicKeyMultibase!.slice(-8)}`;
    const { doc, meta } = await resolveDID(fullLog, { 
      verificationMethod: vmId, 
      versionTime: new Date('2023-02-15T00:00:00Z')
    });
    
    expect(doc.verificationMethod).toHaveLength(2);
    expect(doc.verificationMethod[1].publicKeyMultibase).toBe(authKey2.publicKeyMultibase);
    expect(meta.versionId.split('-')[0]).toBe("2");
  });

  test("Throw error when both verificationMethod and versionNumber are specified", async () => {
    const vmId = `${initialDID}#${authKey1.publicKeyMultibase!.slice(-8)}`;
    let error: Error | null = null;
    
    try {
      await resolveDID(fullLog, { 
        verificationMethod: vmId, 
        versionNumber: 2 
      });
    } catch (e) {
      error = e as Error;
    }

    expect(error).not.toBeNull();
    expect(error?.message).toBe("Cannot specify both verificationMethod and version number/id");
  });
});