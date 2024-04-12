import * as ed from '@noble/ed25519';

import { nanoid } from 'nanoid';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import { canonicalize } from 'json-canonicalize';
import * as jsonpatch from 'fast-json-patch/index.mjs';
import { clone, createDate } from "./utils";
import base32 from 'base32';
import {createHash} from 'node:crypto';
import { base58btc } from "multiformats/bases/base58"

export const PLACEHOLDER = "{{SCID}}";
export const METHOD = "tdw";
export const PROTOCOL = `did:${METHOD}:1`;

const CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"];

export const createSCID = async (logEntryHash: string): Promise<{scid: string}> => {
  return {scid: `${logEntryHash.slice(0, 28)}`};
}

export const deriveHash = async (input: any): Promise<{logEntryHash: string}> => {
  const data = canonicalize(input);
  const hash = createHash('sha256').update(data).digest();
  return {logEntryHash: base32.encode(hash)};
}

export const createDID = async (options: CreateDIDInterface): Promise<{did: string, doc: any, meta: any, log: DIDLog}> => {
  const controller = `did:${METHOD}:${options.domain}:${PLACEHOLDER}`
  let {doc} = await createDIDDoc({...options, controller});
  const {logEntryHash: genesisDocHash} = await deriveHash(doc);
  const {scid} = await createSCID(genesisDocHash);
  doc = JSON.parse(JSON.stringify(doc).replaceAll(PLACEHOLDER, scid));
  const logEntry: DIDLogEntry = [
    scid,
    1,
    createDate(options.created),
    {method: PROTOCOL, scid},
    {value: doc}
  ]
  const {logEntryHash} = await deriveHash(logEntry);
  logEntry[0] = logEntryHash;
  let authKey = {...options.VMs?.find(vm => vm.type === 'authentication')};
  if (!authKey) {
    throw new Error('Auth key not supplied')
  }
  authKey.id = createVMID({...authKey, type: 'authentication'}, doc.id!);
  const signedDoc = await signDocument(doc, {...authKey, type: 'authentication'}, logEntryHash);
  logEntry.push([signedDoc.proof]);
  return {
    did: doc.id!,
    doc,
    meta: {
      versionId: 1,
      created: logEntry[2],
      updated: logEntry[2]
    },
    log: [
      logEntry
    ]
  }
}

export const createDIDDoc = async (options: CreateDIDInterface): Promise<{doc: DIDDoc}> => {
  const {controller} = options;
  const {all} = normalizeVMs(options.VMs, controller);
  return {
    doc: {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
      ],
      id: controller,
      controller,
      ...all
    }
  };
}

export const resolveDID = async (log: DIDLog, options: {versionId?: number, versionTime?: Date} = {}): Promise<{did: string, doc: any, meta: any}> => {
  const resolutionLog = clone(log);
  const protocol = resolutionLog[0][3].method;
  if(protocol !== PROTOCOL) {
    throw new Error(`'${protocol}' protocol unknown.`);
  }
  let versionId = 0;
  let doc: any = {};
  let did = '';
  let scid = '';
  let created = '';
  let updated = '';
  let previousLogEntryHash = '';
  let i = 0;
  for (const entry of resolutionLog) {
    if (entry[1] !== versionId + 1) {
      throw new Error(`versionId '${entry[1]}' in log doesn't match expected '${versionId}'.`);
    }
    versionId = entry[1];
    if (entry[2]) {
      // TODO check timestamps make sense
    }
    updated = entry[2];

    // doc patches & proof
    let newDoc;
    if (versionId === 1) {
      created = entry[2];
      newDoc = entry[4].value;
      scid = entry[3].scid;
      const {logEntryHash} = await deriveHash(
        JSON.parse(JSON.stringify(newDoc).replaceAll(scid, PLACEHOLDER))
      );
      const {scid: derivedScid} = await createSCID(logEntryHash);
      previousLogEntryHash = logEntryHash;
      if (scid !== derivedScid) {
        throw new Error(`SCID '${scid}' not derived from logEntryHash '${logEntryHash}' (scid ${derivedScid})`);
      }
      const authKey = newDoc.verificationMethod.find((vm: VerificationMethod) => vm.id === entry[5][0].verificationMethod);
      const verified = await isDocumentStateValid(authKey, newDoc, entry[5], newDoc);
      if (!verified) {
        throw new Error(`version ${versionId} failed verification of the proof.`)
      }
    } else {
      // versionId > 1
      if (Object.keys(entry[4]).some((k: string) => k === 'value')) {
        newDoc = entry[4].value;
      } else {
        newDoc = jsonpatch.applyPatch(doc, entry[4].patch, false, false).newDocument;
      }
      const {logEntryHash} = await deriveHash([previousLogEntryHash, entry[1], entry[2], entry[3], entry[4]]);
      previousLogEntryHash = logEntryHash;
      if (logEntryHash !== entry[0]) {
        throw new Error(`Hash chain broken at '${versionId}'`);
      }
      const authKey = doc.verificationMethod.find((vm: VerificationMethod) => vm.id === entry[5][0].verificationMethod);
      if (!authKey) {
        throw new Error(`Auth key '${entry[5].verificationMethod}' not found in previous document`);
      }
      const verified = await isDocumentStateValid(authKey, newDoc, entry[5], doc);
      if (!verified) {
        throw new Error(`version ${versionId} failed verification of the proof.`)
      }
    }
    doc = clone(newDoc);
    did = doc.id;
    if (options.versionId === versionId) {
      return {did, doc, meta: {versionId, created, updated, previousLogEntryHash, scid}}
    }
    if (options.versionTime && options.versionTime > new Date(updated)) {
      if (resolutionLog[i+1] && options.versionTime < new Date(resolutionLog[i+1][2])) {
        return {did, doc, meta: {versionId, created, updated, previousLogEntryHash, scid}}
      } else if(!resolutionLog[i+1]) {
        return {did, doc, meta: {versionId, created, updated, previousLogEntryHash, scid}}
      }
    }
    i++;
  }
  if (options.versionTime || options.versionId) {
    throw new Error(`DID with options ${JSON.stringify(options)} not found`);
  }
  return {did, doc, meta: {versionId, created, updated, previousLogEntryHash, scid}}
}

export const updateDID = async (options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: any, log: DIDLog}> => {
  const {log, authKey, context, vms, services, alsoKnownAs, controller, domain} = options;
  let {did, doc, meta} = await resolveDID(log);
  if (domain) {
    did = `did:${METHOD}:${domain}:${log[0][3].scid}`;
  }
  const {all} = normalizeVMs(vms, did);
  const newDoc = {
    ...(context ? {'@context': Array.from(new Set([...CONTEXT, ...context]))} : {'@context': CONTEXT}),
    id: did,
    ...(controller ? {controller: Array.from(new Set([did, ...controller]))} : {controller:[did]}),
    ...all,
    ...(services ? {service: services} : {}),
    ...(alsoKnownAs ? {alsoKnownAs} : {})
  }
  meta.versionId++;
  meta.updated = createDate(options.created);
  const patch = jsonpatch.compare(doc, newDoc);
  const logEntry = [meta.previousLogEntryHash, meta.versionId, meta.updated, {}, {patch: clone(patch)}];
  const {logEntryHash} = await deriveHash(logEntry);
  if(!authKey) {
    throw new Error(`No auth key`);
  }
  authKey.id = authKey.id ?? createVMID({...authKey, type: 'authentication'}, doc.id);
  const signedDoc = await signDocument(newDoc, authKey, logEntryHash);
  return {
    did,
    doc: newDoc,
    meta: {
      versionId: meta.versionId,
      created: meta.created,
      updated: meta.updated,
      previousLogEntryHash: meta.previousLogEntryHash
    },
    log: [
      ...clone(log),
      [logEntryHash, meta.versionId, meta.updated, {}, {patch: clone(patch)}, [signedDoc.proof]]
    ]
  };
}

export const normalizeVMs = (verificationMethod: VerificationMethod[] | undefined, did: string | null = null) => {
  if (!verificationMethod) {
    return {};
  }
  const all: any = {};
  const authentication = verificationMethod
    ?.filter(vm => vm.type === 'authentication').map(vm => createVMID(vm, did))
  if (authentication && authentication?.length > 0) {
    all.authentication = authentication;
  }
  const assertionMethod = verificationMethod
    ?.filter(vm => vm.type === 'assertionMethod').map(vm => createVMID(vm, did))
  if (assertionMethod && assertionMethod?.length > 0) {
    all.assertionMethod = assertionMethod;
  }
  const keyAgreement = verificationMethod
    ?.filter(vm => vm.type === 'keyAgreement').map(vm => createVMID(vm, did));
  if (keyAgreement && keyAgreement?.length > 0) {
    all.keyAgreement = keyAgreement;
  }
  const capabilityDelegation = verificationMethod
    ?.filter(vm => vm.type === 'capabilityDelegation').map(vm => createVMID(vm, did));
  if (capabilityDelegation && capabilityDelegation?.length > 0) {
    all.capabilityDelegation = capabilityDelegation;
  }
  const capabilityInvocation = verificationMethod
  ?.filter(vm => vm.type === 'capabilityInvocation').map(vm => createVMID(vm, did));
  if (capabilityInvocation && capabilityInvocation?.length > 0) {
    all.capabilityInvocation = capabilityInvocation;
  }
  if(verificationMethod && verificationMethod.length > 0) {
    all.verificationMethod = verificationMethod?.map(vm => ({
      id: createVMID(vm, did),
      ...(did ? {controller: vm.controller ?? did} : {}),
      type: 'Multikey',
      publicKeyMultibase: vm.publicKeyMultibase
    }))
  }
  return {all};
}

export const createVMID = (vm: VerificationMethod, did: string | null) => {
  return `${did ?? ''}#${vm.publicKeyMultibase?.slice(-8) || nanoid(8)}`
}

export const signDocument = async (doc: any, vm: VerificationMethod, challenge: string) => {
  try {
    const keyPair = await Ed25519Multikey.from({
      '@context': 'https://w3id.org/security/multikey/v1',
      type: 'Multikey',
      controller: doc.id,
      id: vm.id,
      publicKeyMultibase: vm.publicKeyMultibase,
      secretKeyMultibase: vm.secretKeyMultibase
    });
    // const suite = new DataIntegrityProof({
    //   signer: keyPair.signer(), cryptosuite: eddsa2022CryptoSuite
    // });
    const proof: any = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: vm.id,
      created: createDate(),
      proofPurpose: 'authentication',
      challenge
    }
    const dataHash = createHash('sha256').update(canonicalize(doc)).digest();
    const proofHash = createHash('sha256').update(canonicalize(proof)).digest();
    const input = Buffer.concat([dataHash, proofHash]);
    const secretKey = base58btc.decode(vm.secretKeyMultibase!);

    const output = await ed.signAsync(ed.etc.bytesToHex(input), ed.etc.bytesToHex(secretKey.slice(2, 34)));

    proof.proofValue = base58btc.encode(output);
    return {...doc, proof};
  } catch (e: any) {
    console.error(e)
    throw new Error(`Document signing failure: ${e.details}`)
  }
}

export const isDocumentStateValid = async (authKey: VerificationMethod, doc: any, proofs: any[], prevDoc: any) => {
  if (!isKeyAuthorized(authKey, prevDoc)) {
    throw new Error(`key ${authKey.id} is not authorized to update.`)
  }
  let i = 0;
  while(i < proofs.length) {
    const proof = proofs[i];
    if (proof.type !== 'DataIntegrityProof') {
      throw new Error(`Unknown proof type ${proof.type}`);
    }
    if (proof.proofPurpose !== 'authentication') {
      throw new Error(`Unknown proof purpose] ${proof.proofPurpose}`);
    }
    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error(`Unknown cryptosuite ${proof.cryptosuite}`);
    }
    const publicKey = base58btc.decode(authKey.publicKeyMultibase!);
    const {proofValue, ...restProof} = proof;
    const sig = base58btc.decode(proofValue);
    const dataHash = createHash('sha256').update(canonicalize(doc)).digest();
    const proofHash = createHash('sha256').update(canonicalize(restProof)).digest();
    const input = Buffer.concat([dataHash, proofHash]);

    const verified = await ed.verifyAsync(
      ed.etc.bytesToHex(sig),
      ed.etc.bytesToHex(input),
      ed.etc.bytesToHex(publicKey.slice(2))
    );
    if (!verified) {
      return false;
    }
    i++;
  }
  return true;
}


export const isKeyAuthorized = (authKey: VerificationMethod, prevDoc: any) => {
  return prevDoc.authentication.some((kId: string) => kId === authKey.id);
}
