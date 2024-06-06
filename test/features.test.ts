import { beforeAll, expect, test } from "bun:test";
import { readKeysFromDisk, readLogFromDisk, writeLogToDisk } from "./utils";
import { createDID, resolveDID, updateDID } from "../src/method";
import { createSigner } from "../src/signing";
import { deriveHash } from "../src/utils";

let availableKeys: { ed25519: (VerificationMethod | null)[]; x25519: (VerificationMethod | null)[]};
let log: DIDLog;

beforeAll(async () => {
  const {keys} = readKeysFromDisk();
  availableKeys = JSON.parse(keys);

  const authKey1 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
  const authKey2 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
  const authKey3 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
  const authKey4 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};

  const {doc: newDoc1, log: newLog1} = await createDID({
    domain: 'example.com',
    signer: createSigner(authKey1),
    updateKeys: [`did:key:${authKey1.publicKeyMultibase}`],
    verificationMethods: [authKey1],
    created: new Date('2021-01-01T08:32:55Z')
  });

  const {doc: newDoc2, log: newLog2} = await updateDID({
    log: newLog1,
    signer: createSigner(authKey1),
    updateKeys: [`did:key:${authKey2.publicKeyMultibase}`],
    context: newDoc1['@context'],
    verificationMethods: [authKey2],
    updated: new Date('2021-02-01T08:32:55Z')
  });

  const {doc: newDoc3, log: newLog3} = await updateDID({
    log: newLog2,
    signer: createSigner(authKey2),
    updateKeys: [`did:key:${authKey3.publicKeyMultibase}`],
    context: newDoc2['@context'],
    verificationMethods: [authKey3],
    updated: new Date('2021-03-01T08:32:55Z')
  });

  const {doc: newDoc4, log: newLog4} = await updateDID({
    log: newLog3,
    signer: createSigner(authKey3),
    updateKeys: [`did:key:${authKey4.publicKeyMultibase}`],
    context: newDoc3['@context'],
    verificationMethods: [authKey4],
    updated: new Date('2021-04-01T08:32:55Z')
  });

  log = newLog4;
});

test("Resolve DID at time (first)", async () => {
  const resolved = await resolveDID(log, {versionTime: new Date('2021-01-15T08:32:55Z')});
  expect(resolved.meta.versionId).toBe(1);
});
test("Resolve DID at time (second)", async () => {
  const resolved = await resolveDID(log, {versionTime: new Date('2021-02-15T08:32:55Z')});
  expect(resolved.meta.versionId).toBe(2);
});
test("Resolve DID at time (third)", async () => {
  const resolved = await resolveDID(log, {versionTime: new Date('2021-03-15T08:32:55Z')});
  expect(resolved.meta.versionId).toBe(3);
});
test("Resolve DID at time (last)", async () => {
  const resolved = await resolveDID(log, {versionTime: new Date('2021-04-15T08:32:55Z')});
  expect(resolved.meta.versionId).toBe(4);
});

test("Resolve DID at version", async () => {
  const resolved = await resolveDID(log, {versionId: 1});
  expect(resolved.meta.versionId).toBe(1);
});

test("Resolve DID latest", async () => {
  const resolved = await resolveDID(log);
  expect(resolved.meta.versionId).toBe(4);
});

test("Require `nextKeyHashes` if prerotation enabled in Create", async () => {
  let err: any;
  const authKey1 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
  try {
    const {did, log} = await createDID({
        domain: "example.com",
        signer: createSigner(authKey1),
        updateKeys: [`did:key:${authKey1.publicKeyMultibase}`],
        verificationMethods: [authKey1],
        prerotate: true
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
    [ "5v2bjwgmeqpnuu669zd7956w1w14", 1, "2024-06-06T08:23:06Z", {
        method: "did:tdw:1",
        scid: "5v2bjwgmeqpnuu669zd7956w1w14",
        updateKeys: [ "did:key:z6Mkr2D4ixckmQx8tAVvXEhMuaMhzahxe61qJt7G9vYyiXiJ" ],
        prerotate: true,
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
  const authKey1 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
  const {did, log} = await createDID({
    domain: "example.com",
    signer: createSigner(authKey1),
    updateKeys: [`did:key:${authKey1.publicKeyMultibase}`],
    verificationMethods: [authKey1]
  });
  
  try {
    const {log: updatedLog} = await updateDID({
      log,
      signer: createSigner(authKey1),
      updateKeys: [`did:key:${authKey1.publicKeyMultibase}`],
      verificationMethods: [authKey1],
      prerotate: true
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('nextKeyHashes are required if prerotation enabled')
});

test("Require `nextKeyHashes` if prerotation enabled in Read (when enabled in Update)", async () => {
  let err: any;
  const badLog: DIDLog = [
    [ "0kavr6x6ny2x52uz9m49mrw530mm", 1, "2024-06-06T17:08:22Z", {
        method: "did:tdw:1",
        scid: "0kavr6x6ny2x52uz9m49mrw530mm",
        updateKeys: [ "did:key:z6MkjnDzaWSBfQFmzyPvhcaABbEBQiuCBRdyQNq5kkHS31Z4" ],
      },
      {
        value: {
          "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"
          ],
          id: "did:tdw:example.com:0kavr6x6ny2x52uz9m49mrw530mm",
          controller: "did:tdw:example.com:0kavr6x6ny2x52uz9m49mrw530mm",
          authentication: [ "did:tdw:example.com:0kavr6x6ny2x52uz9m49mrw530mm#kkHS31Z4"
          ],
          verificationMethod: [
            {
              id: "did:tdw:example.com:0kavr6x6ny2x52uz9m49mrw530mm#kkHS31Z4",
              controller: "did:tdw:example.com:0kavr6x6ny2x52uz9m49mrw530mm",
              type: "Multikey",
              publicKeyMultibase: "z6MkjnDzaWSBfQFmzyPvhcaABbEBQiuCBRdyQNq5kkHS31Z4",
            }
          ],
        },
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6MkjnDzaWSBfQFmzyPvhcaABbEBQiuCBRdyQNq5kkHS31Z4",
          created: "2024-06-06T17:08:22Z",
          proofPurpose: "authentication",
          challenge: "vt4e6unqarurbf4zqfahqrkfmc538by1p96z1bv8pxfagr49pfj0",
          proofValue: "z5HBLwQHmrCWFE38VazrBVWv2WMv5QzFcHyasHFcwycWV4fCXGjYgmff7zt3xbRG3f4qRzESaG9DP1yhCVZN9iZec",
        }
      ]
    ], [ "vypfrf9246bt0gxtrve9qg2dn73fnh99mrjw86nyguupgvkgwe40", 2, "2024-06-06T17:08:22Z",
      {
        updateKeys: [ "did:key:z6MkjnDzaWSBfQFmzyPvhcaABbEBQiuCBRdyQNq5kkHS31Z4" ],
        prerotate: true,
      }, {
        patch: [
          {
            op: "replace",
            path: "/controller",
            value: [ "did:tdw:example.com:0kavr6x6ny2x52uz9m49mrw530mm" ],
          }
        ],
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6MkjnDzaWSBfQFmzyPvhcaABbEBQiuCBRdyQNq5kkHS31Z4",
          created: "2024-06-06T17:08:22Z",
          proofPurpose: "authentication",
          challenge: "vypfrf9246bt0gxtrve9qg2dn73fnh99mrjw86nyguupgvkgwe40",
          proofValue: "z4GH9WwT5psNU4a1sVQTtA6RHyecQhpVfSmcqPAh9yhdiCMGr7QtUDmC6bjfZyC3D2BxHZi9AKKQEauj1HF9zLjr3",
        }
      ]
    ]
  ];
  try {
    const {did} = await resolveDID(badLog)
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('prerotate enabled without nextKeyHashes')
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Create", async () => {
  let err: any;
  
  try {
    const authKey1 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
    const authKey2 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
    const authKey3 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
    const {did, log} = await createDID({
      domain: "example.com",
      signer: createSigner(authKey1),
      updateKeys: [`did:key:${authKey1.publicKeyMultibase}`],
      verificationMethods: [authKey1],
      prerotate: true,
      nextKeyHashes: [deriveHash(`did:key:${authKey2.publicKeyMultibase}`)]
    });
    const {log: updatedLog} = await updateDID({
      log,
      signer: createSigner(authKey1),
      updateKeys: [`did:key:${authKey3.publicKeyMultibase}`],
      verificationMethods: [authKey3],
      nextKeyHashes: [deriveHash(`did:key:${authKey3.publicKeyMultibase}`)]
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Read (when enabled in Create)", async () => {
  let err: any;
  const badLog: DIDLog = [
    [ "3npb5kwtyequz8wguewcbhv64866", 1, "2024-06-06T21:15:06Z", {
        method: "did:tdw:1",
        scid: "3npb5kwtyequz8wguewcbhv64866",
        updateKeys: [ "did:key:z6MkkmrDWT9n8rmAVfEvuyBFroc6RFNffAoycrLw4jDJpwPh" ],
        prerotate: true,
        nextKeyHashes: [ "29cbdvcekerkfxv39ec2ew3q93qv78k1pkvv6zybp4cyy1j9qbw0" ],
      },
      {
        value: {
          "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"
          ],
          id: "did:tdw:example.com:3npb5kwtyequz8wguewcbhv64866",
          controller: "did:tdw:example.com:3npb5kwtyequz8wguewcbhv64866",
          authentication: [ "did:tdw:example.com:3npb5kwtyequz8wguewcbhv64866#4jDJpwPh"
          ],
          verificationMethod: [
            {
              id: "did:tdw:example.com:3npb5kwtyequz8wguewcbhv64866#4jDJpwPh",
              controller: "did:tdw:example.com:3npb5kwtyequz8wguewcbhv64866",
              type: "Multikey",
              publicKeyMultibase: "z6MkkmrDWT9n8rmAVfEvuyBFroc6RFNffAoycrLw4jDJpwPh",
            }
          ],
        },
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6MkkmrDWT9n8rmAVfEvuyBFroc6RFNffAoycrLw4jDJpwPh",
          created: "2024-06-06T21:15:06Z",
          proofPurpose: "authentication",
          challenge: "fkyuz1nprhkr8p1faa86rzqabxptp7e15x4e26cbe8zrrytbhv20",
          proofValue: "z2xFMcqPV1J39se3ufho41rs7BtmaNhXeLywmDWqHUb6UWwWtzPHADTKcqqqpjW5zj2VkTMosLnrd4sVwQmRBC2vE",
        }
      ]
    ], [ "dfwf221utarjr9jxd1ywun9wftmgpeybfumqatw1g6rj9u4wdgm0", 2, "2024-06-06T21:15:06Z",
      {
        updateKeys: [ "did:key:z6MkhGC8KFeSQq8y7Jt2wUgyyTgwJAbMt16gKEwCBgxQ25XL" ],
      },
      {
        patch: [
          {
            op: "replace",
            path: "/verificationMethod/0/publicKeyMultibase",
            value: "z6MkhGC8KFeSQq8y7Jt2wUgyyTgwJAbMt16gKEwCBgxQ25XL",
          }, {
            op: "replace",
            path: "/verificationMethod/0/id",
            value: "did:tdw:example.com:3npb5kwtyequz8wguewcbhv64866#BgxQ25XL",
          }, {
            op: "replace",
            path: "/authentication/0",
            value: "did:tdw:example.com:3npb5kwtyequz8wguewcbhv64866#BgxQ25XL",
          }, {
            op: "replace",
            path: "/controller",
            value: [ "did:tdw:example.com:3npb5kwtyequz8wguewcbhv64866" ],
          }
        ],
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6MkkmrDWT9n8rmAVfEvuyBFroc6RFNffAoycrLw4jDJpwPh",
          created: "2024-06-06T21:15:06Z",
          proofPurpose: "authentication",
          challenge: "dfwf221utarjr9jxd1ywun9wftmgpeybfumqatw1g6rj9u4wdgm0",
          proofValue: "z2WVpGENx3Rr2sS3S6puJcGds29FS45c5npgu3m8gJ5PuaN34Htow8uCUu3vD9UZYotbA4t6BmJcGTXrdyWV7ErzM",
        }
      ]
    ]
  ];
  try {
    const {did} = await resolveDID(badLog);
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Update", async () => {
  let err: any;
  
  try {
    const authKey1 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
    const authKey2 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
    const authKey3 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
    const authKey4 = {type: 'authentication' as const, ...availableKeys.ed25519.shift()};
    const {did, log} = await createDID({
      domain: "example.com",
      signer: createSigner(authKey1),
      updateKeys: [`did:key:${authKey1.publicKeyMultibase}`],
      verificationMethods: [authKey1]
    });
    const {log: updatedLog} = await updateDID({
      log,
      signer: createSigner(authKey1),
      updateKeys: [`did:key:${authKey2.publicKeyMultibase}`],
      verificationMethods: [authKey3],
      prerotate: true,
      nextKeyHashes: [deriveHash(`did:key:${authKey3.publicKeyMultibase}`)]
    });
    const {log: updatedLog2} = await updateDID({
      log: updatedLog,
      signer: createSigner(authKey2),
      updateKeys: [`did:key:${authKey4.publicKeyMultibase}`],
      verificationMethods: [authKey3],
      nextKeyHashes: [`did:key:${authKey1.publicKeyMultibase}`]
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
});

test("updateKeys MUST be in nextKeyHashes if prerotation enabled in Read (when enabled in Update)", async () => {
  let err: any;
  const badLog: DIDLog = [
    [ "nrj04rkrgz0aut7detqqtgtv0246", 1, "2024-06-06T21:16:04Z", {
        method: "did:tdw:1",
        scid: "nrj04rkrgz0aut7detqqtgtv0246",
        updateKeys: [ "did:key:z6MktpbfYB3usrBJYN5uEou8o3iFfurWTCWUHEMHUn97YusZ" ],
      },
      {
        value: {
          "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"
          ],
          id: "did:tdw:example.com:nrj04rkrgz0aut7detqqtgtv0246",
          controller: "did:tdw:example.com:nrj04rkrgz0aut7detqqtgtv0246",
          authentication: [ "did:tdw:example.com:nrj04rkrgz0aut7detqqtgtv0246#Un97YusZ"
          ],
          verificationMethod: [
            {
              id: "did:tdw:example.com:nrj04rkrgz0aut7detqqtgtv0246#Un97YusZ",
              controller: "did:tdw:example.com:nrj04rkrgz0aut7detqqtgtv0246",
              type: "Multikey",
              publicKeyMultibase: "z6MktpbfYB3usrBJYN5uEou8o3iFfurWTCWUHEMHUn97YusZ",
            }
          ],
        },
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6MktpbfYB3usrBJYN5uEou8o3iFfurWTCWUHEMHUn97YusZ",
          created: "2024-06-06T21:16:04Z",
          proofPurpose: "authentication",
          challenge: "67rb9gv5qxgjf8fg2je022ju4tquyq5pxkzxr9g348b6h9dr05q0",
          proofValue: "zrGcuVL2H5LFws2uX1wGLwQux3ZFUBcGp6puPEmn1vf1xkPB98Vin72KBvVr5m3ekRoa2NFhXkpHm9K31NpR5dhp",
        }
      ]
    ], [ "24ktmaw8tu1n80fd91tkf82a3qaz10m5j45341x3913e8yxu8eag", 2, "2024-06-06T21:16:04Z",
      {
        updateKeys: [ "did:key:z6MkvVjSMp6xsghjQP54WndyEAjKHduUVxxqm1oMfdPocsYi" ],
        prerotate: true,
        nextKeyHashes: [ "yb6xe3kub8xdwgq4y98jafz5bnb0xydd2b17ymd4607v7k8b4y9g" ],
      },
      {
        patch: [
          {
            op: "replace",
            path: "/verificationMethod/0/publicKeyMultibase",
            value: "z6Mkeh91AZrF2XMrY9P2gVhgwSwZbWyLgTCEUcnjkN4vg2XL",
          }, {
            op: "replace",
            path: "/verificationMethod/0/id",
            value: "did:tdw:example.com:nrj04rkrgz0aut7detqqtgtv0246#kN4vg2XL",
          }, {
            op: "replace",
            path: "/authentication/0",
            value: "did:tdw:example.com:nrj04rkrgz0aut7detqqtgtv0246#kN4vg2XL",
          }, {
            op: "replace",
            path: "/controller",
            value: [ "did:tdw:example.com:nrj04rkrgz0aut7detqqtgtv0246" ],
          }
        ],
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6MktpbfYB3usrBJYN5uEou8o3iFfurWTCWUHEMHUn97YusZ",
          created: "2024-06-06T21:16:04Z",
          proofPurpose: "authentication",
          challenge: "24ktmaw8tu1n80fd91tkf82a3qaz10m5j45341x3913e8yxu8eag",
          proofValue: "z5iZadg1V1U5ESea1y1TX2jzsNjzuemv6PbQo2ZbH9em1qHkmDMG6qQp3MGvTH2YsJMRxZwqsC1UgjVMuxScG1Tpm",
        }
      ]
    ], [ "0utxe7j8dh31r4r3z5tghqqjjq883uey8mnwqtna5y80qeuaev5g", 3, "2024-06-06T21:16:04Z",
      {
        updateKeys: [ "did:key:z6MkrnFAx9KWrcZPhW4HGdVkUqT7Bnzk9Q4DSNHTz9esZP8c" ],
      },
      {
        patch: [],
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6MkvVjSMp6xsghjQP54WndyEAjKHduUVxxqm1oMfdPocsYi",
          created: "2024-06-06T21:16:04Z",
          proofPurpose: "authentication",
          challenge: "0utxe7j8dh31r4r3z5tghqqjjq883uey8mnwqtna5y80qeuaev5g",
          proofValue: "z5KDJTw1C2fRwTsxVzP1GXUJgapWeWxvd5VrwLucY4Pr1fwaMHDQsQwH5cPDdwSNUxiR7LHMUMpvhchDABUW8b2wB",
        }
      ]
    ]
  ];
  try {
    const {did} = await resolveDID(badLog);
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
});
