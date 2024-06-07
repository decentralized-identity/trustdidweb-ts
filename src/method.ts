import * as jsonpatch from 'fast-json-patch/index.mjs';
import { clone, createDate, createDIDDoc, createSCID, createVMID, deriveHash, normalizeVMs } from "./utils";
import { BASE_CONTEXT, METHOD, PLACEHOLDER, PROTOCOL } from './constants';
import { documentStateIsValid, newKeysAreValid } from './assertions';


export const createDID = async (options: CreateDIDInterface): Promise<{did: string, doc: any, meta: any, log: DIDLog}> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied')
  }
  newKeysAreValid(options.updateKeys, [], options.nextKeyHashes ?? [], false, options.prerotate === true); 
  const controller = `did:${METHOD}:${options.domain}:${PLACEHOLDER}`;
  const createdDate = createDate(options.created);
  let {doc} = await createDIDDoc({...options, controller});
  const initialLogEntry: DIDLogEntry = [
    PLACEHOLDER,
    1,
    createdDate,
    {
      method: PROTOCOL,
      scid: PLACEHOLDER,
      updateKeys: options.updateKeys,
      ...(options.prerotate ? {prerotate: true, nextKeyHashes: options.nextKeyHashes} : {})
    },
    {value: doc}
  ]
  const initialLogEntryHash = deriveHash(initialLogEntry);
  const scid = await createSCID(initialLogEntryHash);
  doc = JSON.parse(JSON.stringify(doc).replaceAll(PLACEHOLDER, scid));

  initialLogEntry[0] = scid;
  initialLogEntry[3] = JSON.parse(JSON.stringify(initialLogEntry[3]).replaceAll(PLACEHOLDER, scid));
  initialLogEntry[4] = { value: doc }
  
  const logEntryHash = deriveHash(initialLogEntry);
  const signedDoc = await options.signer(doc, logEntryHash);
  initialLogEntry.push([signedDoc.proof]);
  return {
    did: doc.id!,
    doc,
    meta: {
      versionId: 1,
      created: initialLogEntry[2],
      updated: initialLogEntry[2],
      ...(options.prerotate ? {prerotate: true, nextKeyHashes: options.nextKeyHashes} : {})
    },
    log: [
      initialLogEntry
    ]
  }
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
  let updateKeys = [];
  let previousLogEntryHash = '';
  let i = 0;
  let deactivated: boolean | null = null;
  let prerotate = false;
  let nextKeyHashes: string[] = [];
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
      updateKeys = entry[3].updateKeys;
      prerotate = entry[3].prerotate === true;
      nextKeyHashes = entry[3].nextKeyHashes ?? [];
      newKeysAreValid(updateKeys, [], nextKeyHashes, false, prerotate === true); 
      const logEntryHash = deriveHash(
        [
          PLACEHOLDER,
          1,
          created,
          JSON.parse(JSON.stringify(entry[3]).replaceAll(scid, PLACEHOLDER)),
          {value: JSON.parse(JSON.stringify(newDoc).replaceAll(scid, PLACEHOLDER))}
        ]
      );
      const derivedScid = await createSCID(logEntryHash);
      previousLogEntryHash = derivedScid;
      if (scid !== derivedScid) {
        throw new Error(`SCID '${scid}' not derived from logEntryHash '${logEntryHash}' (scid ${derivedScid})`);
      }
      const verified = await documentStateIsValid(newDoc, entry[5], updateKeys);
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
      if (entry[3].prerotate === true && (!entry[3].nextKeyHashes || entry[3].nextKeyHashes.length === 0)) {
        throw new Error("prerotate enabled without nextKeyHashes");
      }
      newKeysAreValid(entry[3].updateKeys ?? [], nextKeyHashes, entry[3].nextKeyHashes ?? [], prerotate, entry[3].prerotate === true);
      const logEntryHash = deriveHash([
        previousLogEntryHash,
        entry[1],
        entry[2],
        entry[3],
        entry[4]
      ]);
      previousLogEntryHash = logEntryHash;
      if (logEntryHash !== entry[0]) {
        throw new Error(`Hash chain broken at '${versionId}'`);
      }
      const verified = await documentStateIsValid(newDoc, entry[5], updateKeys);
      if (!verified) {
        throw new Error(`version ${versionId} failed verification of the proof.`)
      }
      if (entry[3].updateKeys) {
        updateKeys = entry[3].updateKeys;
      }
      if (entry[3].deactivated === true) {
        deactivated = true;
      }
      if (entry[3].prerotate === true) {
        prerotate = true;
      }
      if (entry[3].nextKeyHashes) {
        nextKeyHashes = entry[3].nextKeyHashes;
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
  return {
    did,
    doc,
    meta: {
      versionId,
      created,
      updated,
      previousLogEntryHash,
      scid,
      prerotate,
      nextKeyHashes,
      ...(deactivated ? {deactivated}: {})
    }
  }
}

export const updateDID = async (options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: any, log: DIDLog}> => {
  const {
    log, updateKeys, context, verificationMethods, services, alsoKnownAs,
    controller, domain, nextKeyHashes, prerotate
  } = options;
  let {did, doc, meta} = await resolveDID(log);
  newKeysAreValid(updateKeys ?? [], meta.nextKeyHashes ?? [], nextKeyHashes ?? [], meta.prerotate === true, prerotate === true);

  if (domain) {
    did = `did:${METHOD}:${domain}:${log[0][3].scid}`;
  }
  const {all} = normalizeVMs(verificationMethods, did);
  const newDoc = {
    ...(context ? {'@context': Array.from(new Set([...BASE_CONTEXT, ...context]))} : {'@context': BASE_CONTEXT}),
    id: did,
    ...(controller ? {controller: Array.from(new Set([did, ...controller]))} : {controller:[did]}),
    ...all,
    ...(services ? {service: services} : {}),
    ...(alsoKnownAs ? {alsoKnownAs} : {})
  }
  meta.versionId++;
  meta.updated = createDate(options.updated);
  const patch = jsonpatch.compare(doc, newDoc);
  const logEntry = [
    meta.previousLogEntryHash,
    meta.versionId,
    meta.updated,
    {
      ...(updateKeys ? {updateKeys} : {}),
      ...(prerotate ? {prerotate: true, nextKeyHashes} : {})
    },
    {patch: clone(patch)}
  ];
  const logEntryHash = deriveHash(logEntry);
  logEntry[0] = logEntryHash;
  const signedDoc = await options.signer(newDoc, logEntryHash);
  logEntry.push([signedDoc.proof])
  return {
    did,
    doc: newDoc,
    meta: {
      versionId: meta.versionId,
      created: meta.created,
      updated: meta.updated,
      previousLogEntryHash: meta.previousLogEntryHash,
      ...(prerotate ? {prerotate: true, nextKeyHashes} : {})
    },
    log: [
      ...clone(log),
      clone(logEntry)
    ]
  };
}

export const deactivateDID = async (options: DeactivateDIDInterface): Promise<{did: string, doc: any, meta: any, log: DIDLog}> => {
  const {log} = options;
  let {did, doc, meta} = await resolveDID(log);
  const newDoc = {
    ...doc,
    authentication: [],
    assertionMethod: [],
    capabilityInvocation: [],
    capabilityDelegation: [],
    keyAgreement: [],
    verificationMethod: [],
  }
  meta.versionId++;
  meta.updated = createDate(meta.created);
  const patch = jsonpatch.compare(doc, newDoc);
  const logEntry = [meta.previousLogEntryHash, meta.versionId, meta.updated, {deactivated: true}, {patch: clone(patch)}];
  const logEntryHash = deriveHash(logEntry);
  logEntry[0] = logEntryHash;
  const signedDoc = await options.signer(newDoc, logEntryHash);
  logEntry.push([signedDoc.proof]);
  return {
    did,
    doc: newDoc,
    meta: {
      versionId: meta.versionId,
      created: meta.created,
      updated: meta.updated,
      previousLogEntryHash: meta.previousLogEntryHash,
      deactivated: true
    },
    log: [
      ...clone(log),
      clone(logEntry)
    ]
  };
}
