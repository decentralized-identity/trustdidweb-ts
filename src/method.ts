import * as jsonpatch from 'fast-json-patch/index.mjs';
import { clone, createDate, createDIDDoc, createSCID, deriveHash, normalizeVMs } from "./utils";
import { BASE_CONTEXT, METHOD, PLACEHOLDER, PROTOCOL } from './constants';
import { documentStateIsValid, hashChainValid, newKeysAreValid, scidIsFromHash } from './assertions';


export const createDID = async (options: CreateDIDInterface): Promise<{did: string, doc: any, meta: any, log: DIDLog}> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied')
  }
  newKeysAreValid(options.updateKeys, [], options.nextKeyHashes ?? [], false, options.prerotation === true); 
  const controller = `did:${METHOD}:${PLACEHOLDER}:${options.domain}`;
  const createdDate = createDate(options.created);
  let {doc} = await createDIDDoc({...options, controller});
  const initialLogEntry: DIDLogEntry = [
    PLACEHOLDER,
    createdDate,
    {
      method: PROTOCOL,
      scid: PLACEHOLDER,
      updateKeys: options.updateKeys,
      portable: options.portable ?? false,
      ...(options.prerotation ? {prerotation: true, nextKeyHashes: options.nextKeyHashes} : {})
    },
    {value: doc}
  ]
  const initialLogEntryHash = deriveHash(initialLogEntry);
  const scid = await createSCID(initialLogEntryHash);
  doc = JSON.parse(JSON.stringify(doc).replaceAll(PLACEHOLDER, scid));

  initialLogEntry[0] = `1-${initialLogEntryHash}`;
  initialLogEntry[2] = JSON.parse(JSON.stringify(initialLogEntry[2]).replaceAll(PLACEHOLDER, scid));
  initialLogEntry[3] = { value: doc }

  const signedDoc = await options.signer(doc, initialLogEntry[0]);
  initialLogEntry.push([signedDoc.proof]);
  return {
    did: doc.id!,
    doc,
    meta: {
      versionId: initialLogEntry[0],
      created: initialLogEntry[1],
      updated: initialLogEntry[1],
      ...(options.prerotation ? {prerotation: true, nextKeyHashes: options.nextKeyHashes} : {})
    },
    log: [
      initialLogEntry
    ]
  }
}

export const resolveDID = async (log: DIDLog, options: {versionNumber?: number, versionId?: string, versionTime?: Date} = {}): Promise<{did: string, doc: any, meta: any}> => {
  const resolutionLog = clone(log);
  const protocol = resolutionLog[0][2].method;
  if(protocol !== PROTOCOL) {
    throw new Error(`'${protocol}' protocol unknown.`);
  }
  let versionId = '';
  let doc: any = {};
  let did = '';
  let scid = '';
  let created = '';
  let updated = '';
  let host = '';
  let updateKeys = [];
  let portable = false;
  let previousLogEntryHash = '';
  let i = 0;
  let deactivated: boolean | null = null;
  let prerotation = false;
  let nextKeyHashes: string[] = [];
  for (const entry of resolutionLog) {
    const [currentVersionId, timestamp, params, data, ...rest] = entry;
    const [version, entryHash] = currentVersionId.split('-');
    if (parseInt(version) !== i + 1) {
      throw new Error(`version '${version}' in log doesn't match expected '${i + 1}'.`);
    }
    versionId = currentVersionId;
    if (timestamp) {
      // TODO check timestamps make sense
    }
    updated = timestamp;

    // doc patches & proof
    let newDoc;
    if (version === '1') {
      created = timestamp;
      newDoc = data.value;
      host = newDoc.id.split(':').at(-1);
      scid = params.scid;
      portable = params.portable ?? portable;
      updateKeys = params.updateKeys;
      prerotation = params.prerotation === true;
      nextKeyHashes = params.nextKeyHashes ?? [];
      newKeysAreValid(updateKeys, [], nextKeyHashes, false, prerotation === true); 
      const logEntryHash = deriveHash(
        [
          PLACEHOLDER,
          created,
          JSON.parse(JSON.stringify(params).replaceAll(scid, PLACEHOLDER)),
          {value: JSON.parse(JSON.stringify(newDoc).replaceAll(scid, PLACEHOLDER))}
        ]
      );
      previousLogEntryHash = logEntryHash;
      if (!await scidIsFromHash(scid, logEntryHash)) {
        throw new Error(`SCID '${scid}' not derived from logEntryHash '${logEntryHash}'`);
      }
      const verified = await documentStateIsValid(newDoc, rest[0], updateKeys);
      if (!verified) {
        throw new Error(`version ${versionId} failed verification of the proof.`)
      }
    } else {
      // version number > 1
      if (Object.keys(data).some((k: string) => k === 'value')) {
        newDoc = data.value;
      } else {
        newDoc = jsonpatch.applyPatch(doc, data.patch, false, false).newDocument;
      }
      if (params.prerotation === true && (!params.nextKeyHashes || params.nextKeyHashes.length === 0)) {
        throw new Error("prerotation enabled without nextKeyHashes");
      }
      const newHost = newDoc.id.split(':').at(-1);
      if (!portable && newHost !== host) {
        throw new Error("Cannot move DID: portability is disabled");
      } else if (newHost !== host) {
        host = newHost;
      }
      newKeysAreValid(params.updateKeys ?? [], nextKeyHashes, params.nextKeyHashes ?? [], prerotation, params.prerotation === true);
      if (!hashChainValid(`${i+1}-${entryHash}`, entry[0])) {
        throw new Error(`Hash chain broken at '${versionId}'`);
      }
      const verified = await documentStateIsValid(newDoc, rest[0], updateKeys);
      if (!verified) {
        throw new Error(`version ${versionId} failed verification of the proof.`)
      }
      if (params.updateKeys) {
        updateKeys = params.updateKeys;
      }
      if (params.deactivated === true) {
        deactivated = true;
      }
      if (params.prerotation === true) {
        prerotation = true;
      }
      if (params.nextKeyHashes) {
        nextKeyHashes = params.nextKeyHashes;
      }
    }
    doc = clone(newDoc);
    did = doc.id;
    if (options.versionNumber === version || options.versionId === versionId) {
      return {did, doc, meta: {versionId, created, updated, previousLogEntryHash, scid}}
    }
    if (options.versionTime && options.versionTime > new Date(updated)) {
      if (resolutionLog[i+1] && options.versionTime < new Date(resolutionLog[i+1][1])) {
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
      prerotation,
      portable,
      nextKeyHashes,
      ...(deactivated ? {deactivated}: {})
    }
  }
}

export const updateDID = async (options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: any, log: DIDLog}> => {
  const {
    log, updateKeys, context, verificationMethods, services, alsoKnownAs,
    controller, domain, nextKeyHashes, prerotation
  } = options;
  let {did, doc, meta} = await resolveDID(log);
  newKeysAreValid(updateKeys ?? [], meta.nextKeyHashes ?? [], nextKeyHashes ?? [], meta.prerotation === true, prerotation === true);

  if (domain) {
    if (!meta.portable) {
      throw new Error(`Cannot move DID: portability is disabled`);
    }
    did = `did:${METHOD}:${domain}:${log[0][2].scid}`;
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
  const [currentVersion] = meta.versionId.split('-');
  const nextVersion = parseInt(currentVersion) + 1;
  meta.updated = createDate(options.updated);
  const patch = jsonpatch.compare(doc, newDoc);
  const logEntry = [
    meta.versionId,
    meta.updated,
    {
      ...(updateKeys ? {updateKeys} : {}),
      ...(prerotation ? {prerotation: true, nextKeyHashes} : {})
    },
    {patch: clone(patch)}
  ];
  const logEntryHash = deriveHash(logEntry);
  logEntry[0] = `${nextVersion}-${logEntryHash}`;
  const signedDoc = await options.signer(newDoc, logEntry[0]);
  logEntry.push([signedDoc.proof])
  return {
    did,
    doc: newDoc,
    meta: {
      versionId: logEntry[0],
      created: meta.created,
      updated: meta.updated,
      previousLogEntryHash: meta.previousLogEntryHash,
      ...(prerotation ? {prerotation: true, nextKeyHashes} : {})
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
  const [currentVersion] = meta.versionId.split('-');
  const nextVersion = parseInt(currentVersion) + 1;
  meta.updated = createDate(meta.created);
  const patch = jsonpatch.compare(doc, newDoc);
  const logEntry = [
    meta.versionId,
    meta.updated,
    {deactivated: true},
    {patch: clone(patch)}
  ];
  const logEntryHash = deriveHash(logEntry);
  logEntry[0] = `${nextVersion}-${logEntryHash}`;
  const signedDoc = await options.signer(newDoc, logEntry[0]);
  logEntry.push([signedDoc.proof]);
  return {
    did,
    doc: newDoc,
    meta: {
      versionId: logEntry[0],
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
