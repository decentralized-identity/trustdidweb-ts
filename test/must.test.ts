import { beforeAll, describe, expect, test } from "bun:test";
import { createDID, deactivateDID, resolveDID, updateDID } from "../src/method";
import { createSigner, generateEd25519VerificationMethod } from "../src/cryptography";


describe("did:tdw normative tests", async () => {
  let newDoc1: any;
  let newLog1: DIDLog;
  let authKey1: VerificationMethod;

  beforeAll(async () => {
    authKey1 = await generateEd25519VerificationMethod('authentication');

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
    const resolved = await resolveDID(newLog1);
    expect(resolved.meta.versionId.split('-')[0]).toBe("1");
  });

  test("Resolve MUST process the DID Log correctly (negative)", async () => {
    let err;
    const malformedLog = "malformed log content";
    try {
      await resolveDID(malformedLog as any);
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
  });

  test("Update implementation MUST generate a correct DID Entry (positive)", async () => {
    const authKey2 = await generateEd25519VerificationMethod('authentication');
    const { doc: updatedDoc, log: updatedLog } = await updateDID({
      log: newLog1,
      signer: createSigner(authKey2),
      updateKeys: [authKey2.publicKeyMultibase!],
      context: newDoc1['@context'],
      verificationMethods: [authKey2],
      updated: new Date('2024-02-01T08:32:55Z')
    });

    expect(updatedLog[1][0]).toBeDefined();
    expect(updatedLog[1][0].split('-')[0]).toBe("2");
  });

  test("Resolver encountering 'deactivated': true MUST return deactivated in metadata (positive)", async () => {
    const { log: updatedLog } = await deactivateDID({
      log: newLog1,
      signer: createSigner(authKey1)
    });
    const resolved = await resolveDID(updatedLog);
    expect(resolved.meta.deactivated).toBe(true);
  });

  test("Resolver encountering 'deactivated': true MUST return deactivated in metadata (negative)", async () => {
    const resolved = await resolveDID(newLog1);
    expect(resolved.meta.deactivated).toBeUndefined();
  });
});
