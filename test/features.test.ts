import { beforeAll, expect, test} from "bun:test";
import { createDID, resolveDIDFromLog, updateDID } from "../src/method";
import { mock } from "bun-bagel";
import { createSigner, generateEd25519VerificationMethod } from "../src/cryptography";
import { deriveHash, createDate, clone, deriveNextKeyHash } from "../src/utils";
import { createMockDIDLog} from './utils';
import type { DIDLog, VerificationMethod } from "../src/interfaces";

let log: DIDLog;
let authKey1: VerificationMethod,
    authKey2: VerificationMethod,
    authKey3: VerificationMethod,
    authKey4: VerificationMethod;

let nonPortableDID: { did: string; doc: any; meta: any; log: DIDLog };
let portableDID: { did: string; doc: any; meta: any; log: DIDLog };

beforeAll(async () => {
  authKey1 = await generateEd25519VerificationMethod();
  authKey2 = await generateEd25519VerificationMethod();
  authKey3 = await generateEd25519VerificationMethod();
  authKey4 = await generateEd25519VerificationMethod();
  
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
  const resolved = await resolveDIDFromLog(log, {versionTime: new Date('2021-01-15T08:32:55Z')});
  expect(resolved.meta.versionId.split('-')[0]).toBe('1');
});

test("Resolve DID at time (second)", async () => {
  const resolved = await resolveDIDFromLog(log, {versionTime: new Date('2021-02-15T08:32:55Z')});
  expect(resolved.meta.versionId.split('-')[0]).toBe('2');
});

test("Resolve DID at time (third)", async () => {
  const resolved = await resolveDIDFromLog(log, {versionTime: new Date('2021-03-15T08:32:55Z')});
  expect(resolved.meta.versionId.split('-')[0]).toBe('3');
});

test("Resolve DID at time (last)", async () => {
  const resolved = await resolveDIDFromLog(log, {versionTime: new Date('2021-04-15T08:32:55Z')});
  expect(resolved.meta.versionId.split('-')[0]).toBe('4');
});

test("Resolve DID at version", async () => {
  const resolved = await resolveDIDFromLog(log, {versionId: log[0].versionId});
  expect(resolved.meta.versionId.split('-')[0]).toBe('1');
});

test("Resolve DID latest", async () => {
  const resolved = await resolveDIDFromLog(log);
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
    {
      versionId: "1-5v2bjwgmeqpnuu669zd7956w1w14",
      versionTime: "2024-06-06T08:23:06Z",
      parameters: {
        method: "did:tdw:0.4",
        scid: "5v2bjwgmeqpnuu669zd7956w1w14",
        updateKeys: [ "z6Mkr2D4ixckmQx8tAVvXEhMuaMhzahxe61qJt7G9vYyiXiJ" ],
        prerotation: true,
      },
      state: {
        "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1" ],
        id: "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14",
        controller: "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14",
        authentication: [ "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14#9vYyiXiJ" ],
        verificationMethod: [
          {
            id: "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14#9vYyiXiJ",
            controller: "did:tdw:example.com:5v2bjwgmeqpnuu669zd7956w1w14",
            type: "Multikey",
            publicKeyMultibase: "z6Mkr2D4ixckmQx8tAVvXEhMuaMhzahxe61qJt7G9vYyiXiJ",
          }
        ],
      },
      proof: [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6Mkr2D4ixckmQx8tAVvXEhMuaMhzahxe61qJt7G9vYyiXiJ",
          created: "2024-06-06T08:23:06Z",
          proofPurpose: "authentication",
          proofValue: "z4wWcu5WXftuvLtZy2jLHiyB8WJoWh8naNu4VFeGdfoBUbFie6mkQYAT2fyLXdbXBpPr7DWdgGatT6NZj7GJGmoBR",
        }
      ]
    }
  ];
  try {
    await resolveDIDFromLog(badLog)
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
  const mockLog: DIDLog = [
    {
      versionId: '1-mock-hash',
      versionTime: createDate(),
      parameters: { method: "did:tdw:0.4", scid: "test-scid" },
      state: { id: "did:tdw:example.com:test-scid" },
      proof: []
    },
    {
      versionId: '2-mock-hash',
      versionTime: createDate().toString(),
      parameters: {prerotation: true},
      state: { id: "did:tdw:example.com:test-scid" },
      proof: []
    },
    {
      versionId: '3-mock-hash',
      versionTime: createDate().toString(),
      parameters: {updateKeys: ['12312312312321']},
      state: { id: "did:tdw:example.com:test-scid" },
      proof: []
    },
  ];
  try {
    process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH = "true";
    process.env.IGNORE_ASSERTION_HASH_CHAIN_IS_VALID = "true";
    const {did} = await resolveDIDFromLog(mockLog)
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('prerotation enabled without nextKeyHashes')
  delete process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH;
  delete process.env.IGNORE_ASSERTION_HASH_CHAIN_IS_VALID;
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
      nextKeyHashes: [await deriveNextKeyHash(authKey2.publicKeyMultibase!)]
    });
    const {log: updatedLog} = await updateDID({
      log,
      signer: createSigner(authKey1),
      updateKeys: [authKey2.publicKeyMultibase!],
      verificationMethods: [authKey2],
      nextKeyHashes: [await deriveNextKeyHash(authKey3.publicKeyMultibase!)]
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('Invalid update key')
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Read (when enabled in Create)", async () => {
  let err: any;
  process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH = "true";
  process.env.IGNORE_ASSERTION_HASH_CHAIN_IS_VALID = "true";
  const mockLog = createMockDIDLog([
    {
      versionId: '1-mock-hash',
      versionTime: createDate(),
      parameters: { updateKeys: ['z6MkrgaxvewsoLCWRn8GnYBGUygJmd5CHUUN46GYSHmQrkC7'], method: "did:tdw:0.4", scid: "test-scid", prerotation: true, nextKeyHashes: ['QmbWm3djZxbAbqZjqFLMP2ywokqFRD2PwoTcUSdbbsdpkM']},
      state: { id: "did:tdw:example.com:test-scid" },
      proof: []
    },
    {
      versionId: '2-mock-hash',
      versionTime: createDate().toString(),
      parameters: {updateKeys: ['z6MkjkTQkTkTh1czqfofbtDFUVEr6Hzzn1zEZ16BYi67TPoE'], nextKeyHashes: ['123']},
      state: { id: "did:tdw:example.com:test-scid" },
      proof: []
    }
  ]);
  try {
    const {did} = await resolveDIDFromLog(mockLog);
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('Invalid update key')
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
      verificationMethods: [authKey2],
      prerotation: true,
      nextKeyHashes: [await deriveHash(authKey3.publicKeyMultibase)]
    });
    const {log: updatedLog2} = await updateDID({
      log: updatedLog,
      signer: createSigner(authKey2),
      updateKeys: [authKey4.publicKeyMultibase!],
      verificationMethods: [authKey3],
      nextKeyHashes: [await deriveNextKeyHash(authKey1.publicKeyMultibase!)]
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('Invalid update key')
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Read (when enabled in Update)", async () => {
  let err: any;
  process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH = "true";
  process.env.IGNORE_ASSERTION_DOCUMENT_STATE_IS_VALID = "true";
  process.env.IGNORE_ASSERTION_HASH_CHAIN_IS_VALID = "true";
  const mockLog = [
    {
      versionId: '1-mock-hash',
      versionTime: createDate(),
      parameters: { method: "did:tdw:0.4", scid: "test-scid" },
      state: { id: "did:tdw:example.com:test-scid" },
      proof: []
    },
    {
      versionId: '2-mock-hash',
      versionTime: createDate().toString(),
      parameters: {prerotation: true, nextKeyHashes: ['1231']},
      state: { id: "did:tdw:example.com:test-scid" },
      proof: []
    },
    {
      versionId: '3-mock-hash',
      versionTime: createDate().toString(),
      parameters: {updateKeys: ['12312312312321'], nextKeyHashes: ['1312311']},
      state: { id: "did:tdw:example.com:test-scid" },
      proof: []
    },
  ];
  try {
    const {did} = await resolveDIDFromLog(mockLog);
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('Invalid update key')
  delete process.env.IGNORE_ASSERTION_SCID_IS_FROM_HASH;
  delete process.env.IGNORE_ASSERTION_DOCUMENT_STATE_IS_VALID;
  delete process.env.IGNORE_ASSERTION_HASH_CHAIN_IS_VALID;
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

    const newEntry = {
      versionId: `${nonPortableDID.log.length + 1}-test`,
      versionTime: newTimestamp,
      parameters: { updateKeys: [authKey1.publicKeyMultibase]},
      state: newDoc,
      proof: [{
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        verificationMethod: `did:key:${authKey1.publicKeyMultibase}`,
        created: newTimestamp,
        proofPurpose: "authentication",
        proofValue: "badProofValue"
      }]
    };

    const badLog: DIDLog = [
      ...nonPortableDID.log as any,
      newEntry
    ];
    await resolveDIDFromLog(badLog);
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
      signer: async (doc: any) => ({
        ...doc,
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: `did:key:${authKey1.publicKeyMultibase}`,
          created: newTimestamp,
          proofPurpose: "authentication",
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

test("Create DID with witnesses", async () => {
  mock("https://example.com/1234/witness", { method: "POST", response: { data: {proof: {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: "did:tdw:1234:example.com:1234#key1",
    created: "2023-06-18T21:19:10Z",
    proofValue: "z58xkL6dbDRJjFVkBxhNHXNHFnZzZk...",
    proofPurpose: "authentication"
  } } }});
  mock("https://example.com/5678/witness", { method: "POST", response: { data: {proof: {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: "did:tdw:5678:example.com:5678#key1",
    created: "2023-06-18T21:19:10Z",
    proofValue: "z58xkL6dbDRJjFVkBxhNHXNHFnZzZk...",
    proofPurpose: "authentication"
  } } }});
  const authKey = await generateEd25519VerificationMethod();
  const { did, doc, meta, log } = await createDID({
    domain: 'example.com',
    signer: createSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: [authKey],
    witnesses: ['did:tdw:1234:example.com:1234', 'did:tdw:5678:example.com:5678'],
    witnessThreshold: 1
  });

  expect(meta.witnesses).toHaveLength(2);
  expect(meta.witnessThreshold).toBe(1);
  expect(log[0].proof?.length).toBe(3);
});

test("Update DID with witnesses", async () => {
  mock("https://example.com/1234/witness", { method: "POST", response: { data: {proof: {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: "did:tdw:1234:example.com:1234#key1",
    created: "2023-06-18T21:19:10Z",
    proofValue: "z58xkL6dbDRJjFVkBxhNHXNHFnZzZk...",
    proofPurpose: "authentication"
  } } }});
  mock("https://example.com/5678/witness", { method: "POST", response: { data: {proof: {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    verificationMethod: "did:tdw:5678:example.com:5678#key1",
    created: "2023-06-18T21:19:10Z",
    proofValue: "z58xkL6dbDRJjFVkBxhNHXNHFnZzZk...",
    proofPurpose: "authentication"
  } } }});
  const authKey = await generateEd25519VerificationMethod();
  const { did, doc, meta, log } = await createDID({
    domain: 'example.com',
    signer: createSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: [authKey]
  });
  
  const { doc: updatedDoc, meta: updatedMeta, log: updatedLog } = await updateDID({
    log,
    signer: createSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    witnesses: ['did:tdw:1234:example.com:1234', 'did:tdw:5678:example.com:5678'],
    witnessThreshold: 2
  });

  expect(updatedMeta.witnesses).toHaveLength(2);
  expect(updatedMeta.witnessThreshold).toBe(2);
  expect(updatedLog[updatedLog.length - 1].proof?.length).toBe(3); // 1 main proof + 2 witness proofs
});

// test("Resolve DID with invalid witness proofs", async () => {
//   // ... setup code to create DID with witnesses

//   // Modify the log to have invalid witness proofs
//   const invalidLog = [...initialLog];
//   invalidLog[invalidLog.length - 1][5] = []; // Empty witness proofs

//   await expect(resolveDIDFromLog(invalidLog)).rejects.toThrow('Invalid witness proofs');
// });