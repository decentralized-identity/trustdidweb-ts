import * as jsonpatch from 'fast-json-patch/index.mjs';
import { beforeAll, expect, mock, test} from "bun:test";
import { createDID, resolveDID, updateDID } from "../src/method";
import { createSigner, generateEd25519VerificationMethod } from "../src/cryptography";
import { deriveHash, createDate, clone } from "../src/utils";
import { newKeysAreValid } from '../src/assertions';
import { createMockDIDLog } from './utils';

let log: DIDLog;
let authKey1: VerificationMethod,
    authKey2: VerificationMethod,
    authKey3: VerificationMethod,
    authKey4: VerificationMethod;

let nonPortableDID: { did: string; doc: any; meta: any; log: DIDLog };
let portableDID: { did: string; doc: any; meta: any; log: DIDLog };

beforeAll(async () => {
  authKey1 = await generateEd25519VerificationMethod('authentication');
  authKey2 = await generateEd25519VerificationMethod('authentication');
  authKey3 = await generateEd25519VerificationMethod('authentication');
  authKey4 = await generateEd25519VerificationMethod('authentication');
  
  const {doc: newDoc1, log: newLog1} = await createDID({
    domain: 'example.com',
    signer: createSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    created: new Date('2021-01-01T08:32:55Z')
  });

  const {doc: newDoc2, log: newLog2} = await updateDID({
    log: newLog1,
    signer: createSigner(authKey1),
    updateKeys: [authKey2.publicKeyMultibase!],
    context: newDoc1['@context'],
    verificationMethods: [authKey2],
    updated: new Date('2021-02-01T08:32:55Z')
  });

  const {doc: newDoc3, log: newLog3} = await updateDID({
    log: newLog2,
    signer: createSigner(authKey2),
    updateKeys: [authKey3.publicKeyMultibase!],
    context: newDoc2['@context'],
    verificationMethods: [authKey3],
    updated: new Date('2021-03-01T08:32:55Z')
  });

  const {doc: newDoc4, log: newLog4} = await updateDID({
    log: newLog3,
    signer: createSigner(authKey3),
    updateKeys: [authKey4.publicKeyMultibase!],
    context: newDoc3['@context'],
    verificationMethods: [authKey4],
    updated: new Date('2021-04-01T08:32:55Z')
  });

  log = newLog4;

  nonPortableDID = await createDID({
    domain: 'example.com',
    signer: createSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    created: new Date('2021-01-01T08:32:55Z'),
    portable: false // Set portable to false
  });

  portableDID = await createDID({
    domain: 'example.com',
    signer: createSigner(authKey2),
    updateKeys: [authKey2.publicKeyMultibase!],
    verificationMethods: [authKey2],
    created: new Date('2021-01-01T08:32:55Z'),
    portable: true // Set portable to true
  });
});

test("Resolve DID at time (first)", async () => {
  const resolved = await resolveDID(log, {versionTime: new Date('2021-01-15T08:32:55Z')});
  expect(resolved.meta.versionId.split('-')[0]).toBe('1');
});

test("Resolve DID at time (second)", async () => {
  const resolved = await resolveDID(log, {versionTime: new Date('2021-02-15T08:32:55Z')});
  expect(resolved.meta.versionId.split('-')[0]).toBe('2');
});

test("Resolve DID at time (third)", async () => {
  const resolved = await resolveDID(log, {versionTime: new Date('2021-03-15T08:32:55Z')});
  expect(resolved.meta.versionId.split('-')[0]).toBe('3');
});

test("Resolve DID at time (last)", async () => {
  const resolved = await resolveDID(log, {versionTime: new Date('2021-04-15T08:32:55Z')});
  expect(resolved.meta.versionId.split('-')[0]).toBe('4');
});

test("Resolve DID at version", async () => {
  const resolved = await resolveDID(log, {versionId: log[0][0]});
  expect(resolved.meta.versionId.split('-')[0]).toBe('1');
});

test("Resolve DID latest", async () => {
  const resolved = await resolveDID(log);
  expect(resolved.meta.versionId.split('-')[0]).toBe('4');
});

test("Require `nextKeyHashes` if prerotation enabled in Create", async () => {
  let err: any;
  try {
    const {did, log} = await createDID({
        domain: "example.com",
        signer: createSigner(authKey1),
        updateKeys: [authKey1.publicKeyMultibase!],
        verificationMethods: [authKey1],
        prerotation: true
      });
    } catch(e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err.message).toContain("nextKeyHashes are required if prerotation enabled");
});

test("Require `nextKeyHashes` if prerotation enabled in Read (when enabled in Create)", async () => {
  let err;
  const badLog: DIDLog = [
    [ "1-5v2bjwgmeqpnuu669zd7956w1w14", "2024-06-06T08:23:06Z", {
        method: "did:tdw:0.3",
        scid: "5v2bjwgmeqpnuu669zd7956w1w14",
        updateKeys: [ "z6Mkr2D4ixckmQx8tAVvXEhMuaMhzahxe61qJt7G9vYyiXiJ" ],
        prerotation: true,
      }, {
        value: {
          "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"
          ],
          id: "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14",
          controller: "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14",
          authentication: [ "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14#9vYyiXiJ"
          ],
          verificationMethod: [
            {
              id: "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14#9vYyiXiJ",
              controller: "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14",
              type: "Multikey",
              publicKeyMultibase: "z6Mkr2D4ixckmQx8tAVvXEhMuaMhzahxe61qJt7G9vYyiXiJ",
            }
          ],
        },
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6Mkr2D4ixckmQx8tAVvXEhMuaMhzahxe61qJt7G9vYyiXiJ",
          created: "2024-06-06T08:23:06Z",
          proofPurpose: "authentication",
          challenge: "yfdr7xm1xf4e8eryw97r3e2yvey4gd13a93me7c6q3r7gfam3bh0",
          proofValue: "z4wWcu5WXftuvLtZy2jLHiyB8WJoWh8naNu4VFeGdfoBUbFie6mkQYAT2fyLXdbXBpPr7DWdgGatT6NZj7GJGmoBR",
        }
      ]
    ]
  ];
  try {
    await resolveDID(badLog)
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
});

test("Require `nextKeyHashes` if prerotation enabled in Update", async () => {
  let err: any;
  const {did, log} = await createDID({
    domain: "example.com",
    signer: createSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1]
  });
  
  try {
    const {log: updatedLog} = await updateDID({
      log,
      signer: createSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: [authKey1],
      prerotation: true
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('nextKeyHashes are required if prerotation enabled')
});

test("Require `nextKeyHashes` if prerotation enabled in Read (when enabled in Update)", async () => {
  let err: any;
  const mockLog = createMockDIDLog([
    ['1-mock-hash', createDate(), { method: "did:tdw:0.3", scid: "test-scid" }, { value: { id: "did:tdw:example.com:test-scid" } } ],
    ['2-mock-hash', createDate().toString(), {prerotation: true}, { patch: [] } ],
    ['3-mock-hash', createDate().toString(), {}, { patch: [] } ],
  ]);
  try {
    process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH = "true";
    const {did} = await resolveDID(mockLog)
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('prerotation enabled without nextKeyHashes')
  delete process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH;
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Create", async () => {
  let err: any;
  
  try {
    const {did, log} = await createDID({
      domain: "example.com",
      signer: createSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: [authKey1],
      prerotation: true,
      nextKeyHashes: [deriveHash(authKey2.publicKeyMultibase)]
    });
    const {log: updatedLog} = await updateDID({
      log,
      signer: createSigner(authKey1),
      updateKeys: [authKey3.publicKeyMultibase!],
      verificationMethods: [authKey3],
      nextKeyHashes: [deriveHash(authKey3.publicKeyMultibase)]
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Read (when enabled in Create)", async () => {
  let err: any;
  process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH = "true";
  const mockLog = createMockDIDLog([
    ['1-mock-hash', createDate(), { method: "did:tdw:0.3", scid: "test-scid", prerotation: true, nextKeyHashes: ['213123123']}, { value: { id: "did:tdw:example.com:test-scid" } } ],
    ['2-mock-hash', createDate().toString(), {updateKeys: ['1213'], nextKeyHashes: ['123']}, { patch: [] } ]
  ]);
  try {
    const {did} = await resolveDID(mockLog);
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
  delete process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH;
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Update", async () => {
  let err: any;
  
  try {
    const {did, log} = await createDID({
      domain: "example.com",
      signer: createSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: [authKey1]
    });
    const {log: updatedLog} = await updateDID({
      log,
      signer: createSigner(authKey1),
      updateKeys: [authKey2.publicKeyMultibase!],
      verificationMethods: [authKey3],
      prerotation: true,
      nextKeyHashes: [deriveHash(authKey3.publicKeyMultibase)]
    });
    const {log: updatedLog2} = await updateDID({
      log: updatedLog,
      signer: createSigner(authKey2),
      updateKeys: [authKey4.publicKeyMultibase!],
      verificationMethods: [authKey3],
      nextKeyHashes: [authKey1.publicKeyMultibase!]
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Read (when enabled in Update)", async () => {
  let err: any;
  process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH = "true";
  const mockLog = createMockDIDLog([
    ['1-mock-hash', createDate(), { method: "did:tdw:0.3", scid: "test-scid" }, { value: { id: "did:tdw:example.com:test-scid" } } ],
    ['2-mock-hash', createDate().toString(), {prerotation: true, nextKeyHashes: ['1231']}, { patch: [] } ],
    ['3-mock-hash', createDate().toString(), {updateKeys: ['12312312312321']}, { patch: [] } ],
  ]);
  try {
    const {did} = await resolveDID(mockLog);
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
  delete process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH;
});

test("DID log with portable false should not resolve if moved", async () => {
  let err: any;
  try {
    const lastEntry = nonPortableDID.log[nonPortableDID.log.length - 1];
    const newTimestamp = createDate(new Date('2021-02-01T08:32:55Z'));
    
    // Create a new document with the moved DID
    const newDoc = {
      ...nonPortableDID.doc,
      id: nonPortableDID.did.replace('example.com', 'newdomain.com')
    };
    // Generate the patch
    const patch = jsonpatch.compare(nonPortableDID.doc, newDoc);

    // Create the new log entry (without the hash and proof initially)
    const newEntry = [
      `${nonPortableDID.log.length + 1}-test`, // Increment the version
      newTimestamp,
      { updateKeys: [authKey1.publicKeyMultibase]},
      { patch },
      {
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        verificationMethod: authKey1.publicKeyMultibase,
        created: newTimestamp,
        proofPurpose: "authentication",
        challenge: '1-test',
        proofValue: "z5KDJTw1C2fRwTsxVzP1GXUJgapWeWxvd5VrwLucY4Pr1fwaMHDQsQwH5cPDdwSNUxiR7LHMUMpvhchDABUW8b2wB"
      }
    ];

    const badLog: DIDLog = [
      ...nonPortableDID.log as any,
      newEntry
    ];

    await resolveDID(badLog);
  } catch (e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('Cannot move DID: portability is disabled');
});

test("updateDID should not allow moving a non-portable DID", async () => {
  let err: any;
  try {
    const newTimestamp = createDate(new Date('2021-02-01T08:32:55Z'));
    const newDomain = 'newdomain.com';
    
    const updateOptions = {
      log: clone(nonPortableDID.log),
      updateKeys: [authKey1.publicKeyMultibase!],
      domain: newDomain,
      updated: newTimestamp,
      signer: async (doc: any, challenge: string) => ({
        ...doc,
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: `did:key:${authKey1.publicKeyMultibase}`,
          created: newTimestamp,
          proofPurpose: "authentication",
          challenge,
          proofValue: "z5KDJTw1C2fRwTsxVzP1GXUJgapWeWxvd5VrwLucY4Pr1fwaMHDQsQwH5cPDdwSNUxiR7LHMUMpvhchDABUW8b2wB"
        }
      })
    };

    await updateDID(updateOptions);
  } catch (e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('Cannot move DID: portability is disabled');
});