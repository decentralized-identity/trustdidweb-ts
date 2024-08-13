import { test, expect, beforeAll } from "bun:test";
import { createDID, deactivateDID, resolveDID, updateDID } from "../src/method";
import fs from 'node:fs';
import { readLogFromDisk } from "./utils";
import { createVMID, deriveHash } from "../src/utils";
import { METHOD } from "../src/constants";
import { createSigner, generateEd25519VerificationMethod, generateX25519VerificationMethod } from "../src/cryptography";

let docFile: string, logFile: string;
let did: string;
let currentAuthKey: VerificationMethod | null = null;

const verboseMode = Bun.env['LOG_RESOLVES'] === 'true';

const logFilePath =
  (id: string, version?: number) =>
    `./test/logs/${id}/did${verboseMode && version ? '.' + version : ''}.jsonl`;

const writeFilesToDisk = (_log: DIDLog, _doc: any, version: number) => {
  let id = _doc.id.split(':').at(-2);
  if (verboseMode) {
    id = 'test-run';
  }
  docFile = `./test/logs/${id}/did${verboseMode ? '.' + version : ''}.json`;
  logFile = logFilePath(id, version);
  fs.mkdirSync(`./test/logs/${id}`, {recursive: true});
  fs.writeFileSync(docFile, JSON.stringify(_doc, null, 2));
  fs.writeFileSync(logFile, JSON.stringify(_log.shift()) + '\n');
  for (const entry of _log) {
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  }
}


const testResolveVersion = async (version: number) => {
  const log = readLogFromDisk(logFile);
  const {did: resolvedDID, doc: resolvedDoc, meta} = await resolveDID(log, {versionNumber: version});

  if(verboseMode) {
    console.log(`Resolved DID Document: ${version}`, resolvedDID, resolvedDoc);
  }

  expect(resolvedDoc.id).toBe(resolvedDID);
  expect(meta.versionId.split('-')[0]).toBe(version.toString());
  expect(resolvedDoc.proof).toBeUndefined();
}

beforeAll(async () => {
  currentAuthKey = await generateEd25519VerificationMethod('authentication');
});

test("Create DID (2 keys + domain)", async () => {
  const {did: newDID, doc: newDoc, meta, log: newLog} = await createDID({
    domain: 'example.com',
    signer: createSigner(currentAuthKey!),
    updateKeys: [currentAuthKey!.publicKeyMultibase!],
    portable: true,
    verificationMethods: [
      currentAuthKey!,
      await generateEd25519VerificationMethod('assertionMethod')
    ]});
  did = newDID;
  currentAuthKey!.controller = did;
  currentAuthKey!.id = createVMID(currentAuthKey!, did);

  expect(newDID).toContain('example.com');
  expect(newDID.split(':').length).toBe(4);
  expect(newDID.split(':').at(-2)?.length).toBe(46);
  expect(newDoc.verificationMethod.length).toBe(2);
  expect(newDoc.id).toBe(newDID);
  expect(newLog.length).toBe(1);
  
  expect(newLog[0][0]).toBe(meta.versionId);
  expect(newLog[0][1]).toBe(meta.created);
  expect(newLog[0][2].method).toBe(`did:${METHOD}:0.3`);
  expect(newLog[0][2].portable).toBe(true);

  writeFilesToDisk(newLog, newDoc, 1);
});

test("Resolve DID version 1", async () => {
  await testResolveVersion(1);
});

test("Update DID (2 keys, 1 service, change domain)", async () => {
  const nextAuthKey = await generateEd25519VerificationMethod('authentication');
  const didLog = readLogFromDisk(logFile);
  const context = ["https://identity.foundation/linked-vp/contexts/v1"];

  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      signer: createSigner(currentAuthKey!),
      updateKeys: [nextAuthKey.publicKeyMultibase!],
      context,
      domain: 'localhost%3A8000',
      verificationMethods: [
        nextAuthKey,
        await generateEd25519VerificationMethod('assertionMethod')
      ],
      services: [
        {
          "id": `${did}#whois`,
          "type": "LinkedVerifiablePresentation",
          "serviceEndpoint": [`https://example.com/docs/${did.split(':').at(-1)}/whois.json`]
        }
      ]
    });

  expect(updatedDID).toContain('localhost%3A8000');
  expect(updatedDoc.service.length).toBe(1);
  expect(updatedDoc.service[0].id).toBe(`${did}#whois`);
  expect(updatedDoc.service[0].type).toBe('LinkedVerifiablePresentation');
  expect(updatedDoc.service[0].serviceEndpoint).toContain(`https://example.com/docs/${did.split(':').at(-1)}/whois.json`);
  expect(meta.versionId.split('-')[0]).toBe("2");

  writeFilesToDisk(updatedLog, updatedDoc, 2);
  did = updatedDID;
  currentAuthKey = nextAuthKey;
});

test("Resolve DID version 2", async () => {
  await testResolveVersion(2);
});

test("Update DID (3 keys, 2 services)", async () => {
  const nextAuthKey = await generateEd25519VerificationMethod('authentication');
  const didLog = readLogFromDisk(logFile);
  const {doc} = await resolveDID(didLog);

  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      signer: createSigner(currentAuthKey!),
      updateKeys: [nextAuthKey.publicKeyMultibase!],
      context: [...doc['@context'], 'https://didcomm.org/messaging/v2'],
      verificationMethods: [
        nextAuthKey,
        await generateEd25519VerificationMethod('assertionMethod'),
        await generateX25519VerificationMethod('keyAgreement')
      ],
      services: [
        ...doc.service,
        {
          id: `${did}#didcomm`,
          type: 'DIDCommMessaging',
          serviceEndpoint: {
            "uri": "https://example.com/didcomm",
            "accept": [
                "didcomm/v2",
                "didcomm/aip2;env=rfc587"
            ],
            "routingKeys": ["did:example:somemediator#somekey"]
          }
        }
      ]});
  expect(updatedDID).toBe(did);
  expect(updatedDoc.keyAgreement.length).toBe(1)
  expect(updatedDoc.service.length).toBe(2);
  expect(updatedDoc.service[1].id).toBe(`${did}#didcomm`);
  expect(updatedDoc.service[1].type).toBe('DIDCommMessaging');
  expect(updatedDoc.service[1].serviceEndpoint.uri).toContain(`https://example.com/didcomm`);
  expect(meta.versionId.split('-')[0]).toBe("3");

  writeFilesToDisk(updatedLog, updatedDoc, 3);
  currentAuthKey = nextAuthKey;
});

test("Resolve DID version 3", async () => {
  await testResolveVersion(3);
});

test("Update DID (add alsoKnownAs)", async () => {
  const nextAuthKey = await generateEd25519VerificationMethod('authentication');
  const didLog = readLogFromDisk(logFile);
  const {doc} = await resolveDID(didLog);

  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      signer: createSigner(currentAuthKey!),
      updateKeys: [nextAuthKey.publicKeyMultibase!],
      context: doc['@context'],
      verificationMethods: [
        nextAuthKey,
        await generateEd25519VerificationMethod('assertionMethod'),
        await generateX25519VerificationMethod('keyAgreement')
      ],
      services: doc.service,
      alsoKnownAs: ['did:web:example.com']
    });
  expect(updatedDID).toBe(did);
  expect(updatedDoc.alsoKnownAs).toContain('did:web:example.com')
  expect(meta.versionId.split('-')[0]).toBe("4");

  writeFilesToDisk(updatedLog, updatedDoc, 4);
  currentAuthKey = nextAuthKey;
});

test("Resolve DID version 4", async () => {
  await testResolveVersion(4);
});

test("Update DID (add external controller)", async () => {
  let didLog = readLogFromDisk(logFile);
  const {doc} = await resolveDID(didLog);
  const nextAuthKey = await generateEd25519VerificationMethod('authentication');
  const externalAuthKey = await generateEd25519VerificationMethod('authentication');
  externalAuthKey.controller = externalAuthKey.publicKeyMultibase;
  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      signer: createSigner(currentAuthKey!),
      updateKeys: [
        nextAuthKey.publicKeyMultibase!,
        externalAuthKey.publicKeyMultibase!
      ],
      controller: [
        ...(Array.isArray(doc.controller) ? doc.controller : [doc.controller]),
        externalAuthKey.controller
      ],
      context: doc['@context'],
      verificationMethods: [
        nextAuthKey,
        externalAuthKey
      ],
      services: doc.service,
      alsoKnownAs: ['did:web:example.com']
    });
    didLog = [...updatedLog];
    expect(updatedDID).toBe(did);
    expect(updatedDoc.controller).toContain(externalAuthKey.controller);
    expect(updatedDoc.authentication[1].slice(-6)).toBe(externalAuthKey.controller!.slice(-6));
    expect(updatedDoc.verificationMethod[1].controller).toBe(externalAuthKey.controller);

    expect(meta.versionId.split('-')[0]).toBe("5");
    
    writeFilesToDisk(updatedLog, updatedDoc, 5);
    currentAuthKey = nextAuthKey;
});

test("Resolve DID version 5", async () => {
  await testResolveVersion(5);
});

test("Update DID (enable prerotation)", async () => {
  let didLog = readLogFromDisk(logFile);
  const {doc} = await resolveDID(didLog);

  const nextAuthKey = await generateEd25519VerificationMethod('authentication');
  const nextNextAuthKey = await generateEd25519VerificationMethod('authentication');
  const nextNextKeyHash = deriveHash(nextNextAuthKey.publicKeyMultibase);
  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await updateDID({
      log: didLog,
      signer: createSigner(currentAuthKey!),
      updateKeys: [
        nextAuthKey.publicKeyMultibase!
      ],
      prerotation: true,
      nextKeyHashes: [nextNextKeyHash],
      context: doc['@context'],
      verificationMethods: [
        nextAuthKey
      ],
      services: doc.service,
      alsoKnownAs: ['did:web:example.com']
    });
    didLog = [...updatedLog];
    expect(updatedDID).toBe(did);
    expect(updatedDoc.controller).toContain(did)
    expect(meta.prerotation).toBe(true);
    expect(meta.nextKeyHashes).toContain(nextNextKeyHash);

    expect(meta.versionId.split('-')[0]).toBe("6");
    
    writeFilesToDisk(updatedLog, updatedDoc, 6);
    currentAuthKey = nextAuthKey;
});

test("Resolve DID version 6", async () => {
  await testResolveVersion(6);
});

// ADD ANY NEW TESTS HERE AND BUMP VERSION NUMBER AT END OF FILE

test("Deactivate DID", async () => {
  let didLog = readLogFromDisk(logFile);
  const {doc} = await resolveDID(didLog);
  const {did: updatedDID, doc: updatedDoc, meta, log: updatedLog} =
    await deactivateDID({
      log: didLog,
      signer: createSigner(currentAuthKey!)
    });
    didLog = [...updatedLog];
    expect(updatedDID).toBe(did);
    expect(updatedDoc.controller).toEqual(expect.arrayContaining(doc.controller));
    expect(updatedDoc.controller.length).toEqual(doc.controller.length);
    expect(updatedDoc.authentication.length).toBe(0);
    expect(updatedDoc.verificationMethod.length).toBe(0);
    expect(meta.deactivated).toBe(true);

    expect(meta.versionId.split('-')[0]).toBe("7");
    
    writeFilesToDisk(updatedLog, updatedDoc, 7);
});

test("Resolve DID version 7", async () => {
  await testResolveVersion(7);
});
