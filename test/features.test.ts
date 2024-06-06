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

test("Require `nextKeys` if prerotation enabled in Create", async () => {
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
    expect(err.message).toContain("nextKeys are required if prerotation enabled");
});

test("Require `nextKeys` if prerotation enabled in Read (when enabled in Create)", async () => {
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

test("Require `nextKeys` if prerotation enabled in Update", async () => {
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
  expect(err.message).toContain('nextKeys are required if prerotation enabled')
});

test("Require `nextKeys` if prerotation enabled in Read (when enabled in update)", async () => {
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
  expect(err.message).toContain('prerotate enabled without nextKeys')
});

test("updateKeys MUST be in nextKeys if prerotation enabled in Create", async () => {
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
      nextKeys: [deriveHash(`did:key:${authKey2.publicKeyMultibase}`)]
    });
    const {log: updatedLog} = await updateDID({
      log,
      signer: createSigner(authKey1),
      updateKeys: [`did:key:${authKey3.publicKeyMultibase}`],
      verificationMethods: [authKey3],
      nextKeys: [deriveHash(`did:key:${authKey3.publicKeyMultibase}`)]
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
});

test("updateKeys MUST be in nextKeys if prerotation enabled in Read (when enabled in Create)", async () => {
  let err: any;
  const badLog: DIDLog = [
    [ "tt3y1vvwmz7zff0hb21p291ybpga", 1, "2024-06-06T21:06:12Z", {
        method: "did:tdw:1",
        scid: "tt3y1vvwmz7zff0hb21p291ybpga",
        updateKeys: [ "did:key:z6MkkmrDWT9n8rmAVfEvuyBFroc6RFNffAoycrLw4jDJpwPh" ],
        prerotate: true,
        nextKeys: [ "29cbdvcekerkfxv39ec2ew3q93qv78k1pkvv6zybp4cyy1j9qbw0" ],
      }, {
        value: {
          "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"
          ],
          id: "did:tdw:example.com:tt3y1vvwmz7zff0hb21p291ybpga",
          controller: "did:tdw:example.com:tt3y1vvwmz7zff0hb21p291ybpga",
          authentication: [ "did:tdw:example.com:tt3y1vvwmz7zff0hb21p291ybpga#4jDJpwPh"
          ],
          verificationMethod: [
            {
              id: "did:tdw:example.com:tt3y1vvwmz7zff0hb21p291ybpga#4jDJpwPh",
              controller: "did:tdw:example.com:tt3y1vvwmz7zff0hb21p291ybpga",
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
          created: "2024-06-06T21:06:12Z",
          proofPurpose: "authentication",
          challenge: "bgnqfx0hznvdy3jqghgh89rftchn1becq3ydd66fyh3h0d4a8440",
          proofValue: "z4h9rYPQPm55M4sUCv683kCgdiAAL6KhsDirvg1ggrT7hmPMSzshqCrNCGPkD2S7TPMBn5Mwd9JfH8NesR2mMo5Up",
        }
      ] ], [ "uj81kwj0x8dypxg50g3qj2mjj1exk0kz6474zc2qmjbzye7t1a90", 2, "2024-06-06T21:06:12Z",
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
            value: "did:tdw:example.com:tt3y1vvwmz7zff0hb21p291ybpga#BgxQ25XL",
          }, {
            op: "replace",
            path: "/authentication/0",
            value: "did:tdw:example.com:tt3y1vvwmz7zff0hb21p291ybpga#BgxQ25XL",
          }, {
            op: "replace",
            path: "/controller",
            value: [ "did:tdw:example.com:tt3y1vvwmz7zff0hb21p291ybpga" ],
          }
        ],
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6MkkmrDWT9n8rmAVfEvuyBFroc6RFNffAoycrLw4jDJpwPh",
          created: "2024-06-06T21:06:12Z",
          proofPurpose: "authentication",
          challenge: "uj81kwj0x8dypxg50g3qj2mjj1exk0kz6474zc2qmjbzye7t1a90",
          proofValue: "z4PQiE11c8MJ6TahFNyKLL185tz3pkQnbUURKQ8LwEmo2BvGpzLGHhByq1nRpdZf4hhTcGgwxgPD616N9XtyRgYi7",
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

test("updateKeys MUST be in nextKeys if prerotation enabled in Update", async () => {
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
      nextKeys: [deriveHash(`did:key:${authKey3.publicKeyMultibase}`)]
    });
    const {log: updatedLog2} = await updateDID({
      log: updatedLog,
      signer: createSigner(authKey2),
      updateKeys: [`did:key:${authKey4.publicKeyMultibase}`],
      verificationMethods: [authKey3],
      nextKeys: [`did:key:${authKey1.publicKeyMultibase}`]
    });
  } catch(e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('invalid updateKeys')
});

test("updateKeys MUST be in nextKeys if prerotation enabled in Read (when enabled in Update)", async () => {
  let err: any;
  const badLog: DIDLog = [
    [ "7kana772j1zd4n4d8tq5fkkyzygh", 1, "2024-06-06T21:08:24Z", {
        method: "did:tdw:1",
        scid: "7kana772j1zd4n4d8tq5fkkyzygh",
        updateKeys: [ "did:key:z6MktpbfYB3usrBJYN5uEou8o3iFfurWTCWUHEMHUn97YusZ" ],
      },
      {
        value: {
          "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"
          ],
          id: "did:tdw:example.com:7kana772j1zd4n4d8tq5fkkyzygh",
          controller: "did:tdw:example.com:7kana772j1zd4n4d8tq5fkkyzygh",
          authentication: [ "did:tdw:example.com:7kana772j1zd4n4d8tq5fkkyzygh#Un97YusZ"
          ],
          verificationMethod: [
            {
              id: "did:tdw:example.com:7kana772j1zd4n4d8tq5fkkyzygh#Un97YusZ",
              controller: "did:tdw:example.com:7kana772j1zd4n4d8tq5fkkyzygh",
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
          created: "2024-06-06T21:08:24Z",
          proofPurpose: "authentication",
          challenge: "y5dbjd7z6qqu22wc010d05vcgx190amnvng6gvgdvkexdgynvzgg",
          proofValue: "z2D78Yny7AWVsebXJ2J1WXMMpnXnQBFnR25jpHpr99DxfF4aBzw1rLGqzbPL99h43MbhtC5n4RxxJQNYeBjnyEReZ",
        }
      ]
    ], [ "kpwn32hc2r9ge18txh3cg0z6dybev9jqdmxv8my92qyd79afq4bg", 2, "2024-06-06T21:08:24Z",
      {
        updateKeys: [ "did:key:z6MkvVjSMp6xsghjQP54WndyEAjKHduUVxxqm1oMfdPocsYi" ],
        prerotate: true,
        nextKeys: [ "yb6xe3kub8xdwgq4y98jafz5bnb0xydd2b17ymd4607v7k8b4y9g" ],
      }, {
        patch: [
          {
            op: "replace",
            path: "/verificationMethod/0/publicKeyMultibase",
            value: "z6Mkeh91AZrF2XMrY9P2gVhgwSwZbWyLgTCEUcnjkN4vg2XL",
          }, {
            op: "replace",
            path: "/verificationMethod/0/id",
            value: "did:tdw:example.com:7kana772j1zd4n4d8tq5fkkyzygh#kN4vg2XL",
          }, {
            op: "replace",
            path: "/authentication/0",
            value: "did:tdw:example.com:7kana772j1zd4n4d8tq5fkkyzygh#kN4vg2XL",
          }, {
            op: "replace",
            path: "/controller",
            value: [ "did:tdw:example.com:7kana772j1zd4n4d8tq5fkkyzygh" ],
          }
        ],
      }, [
        {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: "did:key:z6MktpbfYB3usrBJYN5uEou8o3iFfurWTCWUHEMHUn97YusZ",
          created: "2024-06-06T21:08:24Z",
          proofPurpose: "authentication",
          challenge: "kpwn32hc2r9ge18txh3cg0z6dybev9jqdmxv8my92qyd79afq4bg",
          proofValue: "z4AiFRGhnbqa1CkELtQ8vtVKSMaJJfWyiMhN65krvZZNweNtpW5gA8pMFHc87YzUWx7bgZAMcYHMtfgHCp6EEBsyK",
        }
      ]
    ], [ "9zf4kumwc4paq33wg694w1ranw5vap72am8fqcmb210274cfpzug", 3, "2024-06-06T21:08:24Z",
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
          created: "2024-06-06T21:08:24Z",
          proofPurpose: "authentication",
          challenge: "9zf4kumwc4paq33wg694w1ranw5vap72am8fqcmb210274cfpzug",
          proofValue: "zBJ6cZhooNe1yfgTDALDRKwAfizfQXZqjYci9XAs3S3FDGwDsyKAKrfuCW5iQPQB5jfg8ipjSc8Hatef1veLKAsK",
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
