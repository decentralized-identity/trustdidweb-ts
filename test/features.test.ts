import { beforeAll, expect, test } from "bun:test";
import { readKeysFromDisk, readLogFromDisk, writeLogToDisk } from "./utils";
import { createDID, resolveDID, updateDID } from "../src/method";

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
    VMs: [authKey1],
    created: new Date('2021-01-01T08:32:55Z')
  });

  const {doc: newDoc2, log: newLog2} = await updateDID({
    log: newLog1,
    authKey: authKey1,
    context: newDoc1['@context'],
    vms: [authKey2],
    created: new Date('2021-02-01T08:32:55Z')
  });

  const {doc: newDoc3, log: newLog3} = await updateDID({
    log: newLog2,
    authKey: authKey2,
    context: newDoc2['@context'],
    vms: [authKey3],
    created: new Date('2021-03-01T08:32:55Z')
  });

  const {doc: newDoc4, log: newLog4} = await updateDID({
    log: newLog3,
    authKey: authKey3,
    context: newDoc3['@context'],
    vms: [authKey4],
    created: new Date('2021-04-01T08:32:55Z')
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