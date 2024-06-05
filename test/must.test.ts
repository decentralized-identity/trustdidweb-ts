import { beforeAll, describe, expect, test } from "bun:test";
import { readKeysFromDisk, readLogFromDisk, writeLogToDisk } from "./utils";
import { createDID, deactivateDID, resolveDID, updateDID } from "../src/method";
import { createSigner } from "../src/signing";

let availableKeys: { ed25519: (VerificationMethod | null)[]; x25519: (VerificationMethod | null)[] };

describe("did:tdw normative tests", async () => {
  let newDoc1: any;
  let newLog1: DIDLog;
  let authKey1: VerificationMethod;

  beforeAll(async () => {
    const { keys } = readKeysFromDisk();
    availableKeys = JSON.parse(keys);

    authKey1 = { type: 'authentication' as const, ...availableKeys.ed25519.shift() };

    const { doc, log } = await createDID({
      domain: 'example.com',
      signer: createSigner(authKey1),
      updateKeys: [`did:key:${authKey1.publicKeyMultibase}`],
      verificationMethods: [authKey1],
      created: new Date('2024-01-01T08:32:55Z')
    });

    newDoc1 = doc;
    newLog1 = log;
  });

  test("DIDDoc MUST contain at least one authentication or verificationMethod key type (positive)", async () => {
    const resolved = await resolveDID(newLog1);
    expect(resolved.doc.verificationMethod.length).toBeGreaterThan(0);
  });

  test("DIDDoc MUST contain at least one authentication or verificationMethod key type (negative)", async () => {
    let err;
    const authKey1 = { type: 'authentication' as const, ...availableKeys.ed25519.shift() };

    try {
      await createDID({
        domain: "example.com",
        signer: createSigner(authKey1),
        updateKeys: [`did:key:${authKey1.publicKeyMultibase}`],
        verificationMethods: [],
        created: new Date('2024-01-01T08:32:55Z')
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
  });

  test("Resolve MUST process the DID Log correctly (positive)", async () => {
    const resolved = await resolveDID(newLog1);
    expect(resolved.meta.versionId).toBe(1);
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
    const authKey2 = { type: 'authentication' as const, ...availableKeys.ed25519.shift() };
    const { doc: updatedDoc, log: updatedLog } = await updateDID({
      log: newLog1,
      signer: createSigner(authKey2),
      updateKeys: [`did:key:${authKey2.publicKeyMultibase}`],
      context: newDoc1['@context'],
      verificationMethods: [authKey2],
      updated: new Date('2024-02-01T08:32:55Z')
    });

    expect(updatedLog[1][0]).toBeDefined();
    expect(updatedLog[1][1]).toBe(2);
  });

  test("Update implementation MUST generate a correct DID Entry (negative)", async () => {
    let err;

    try {
      await updateDID({
        log: newLog1,
        signer: createSigner(authKey1),
        updateKeys: [`did:key:${authKey1.publicKeyMultibase}`],
        context: newDoc1['@context'],
        verificationMethods: [],
        updated: new Date('2024-02-01T08:32:55Z')
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
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