import * as jsonpatch from 'fast-json-patch/index.mjs';
import { clone, collectWitnessProofs, createDate, createDIDDoc, createSCID, deriveHash, findVerificationMethod, normalizeVMs } from "./utils";
import { BASE_CONTEXT, METHOD, PLACEHOLDER, PROTOCOL } from './constants';
import { documentStateIsValid, hashChainValid, newKeysAreValid, scidIsFromHash } from './assertions';


export const createDID = async (options: CreateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied')
  }
  newKeysAreValid(options.updateKeys, [], options.nextKeyHashes ?? [], false, options.prerotation === true); 
  const controller = `did:${METHOD}:${PLACEHOLDER}:${options.domain}`;
  const createdDate = createDate(options.created);
  let {doc} = await createDIDDoc({...options, controller});
  const params = {
    scid: PLACEHOLDER,
    updateKeys: options.updateKeys,
    portable: options.portable ?? false,
    ...(options.prerotation ? {prerotation: true, nextKeyHashes: options.nextKeyHashes ?? []} : {prerotation: false, nextKeyHashes: []}),
    ...(options.witnesses ? {
      witnesses: options.witnesses,
      witnessThreshold: options.witnessThreshold || options.witnesses.length
    } : {
      witnesses: [],
      witnessThreshold: 0
    }),
    deactivated: false
  };
  const initialLogEntry: DIDLogEntry = [
    PLACEHOLDER,
    createdDate,
    {
      method: PROTOCOL,
      ...params
    },
    {value: doc}
  ]
  const initialLogEntryHash = deriveHash(initialLogEntry);
  params.scid = await createSCID(initialLogEntryHash);
  doc = JSON.parse(JSON.stringify(doc).replaceAll(PLACEHOLDER, params.scid));

  initialLogEntry[0] = `1-${initialLogEntryHash}`;
  initialLogEntry[2] = JSON.parse(JSON.stringify(initialLogEntry[2]).replaceAll(PLACEHOLDER, params.scid));
  initialLogEntry[3] = { value: doc }

  const signedDoc = await options.signer(doc, initialLogEntry[0]);
  let allProofs = [signedDoc.proof];
  initialLogEntry.push(allProofs);

  if (options.witnesses && options.witnesses.length > 0) {
    const witnessProofs = await collectWitnessProofs(options.witnesses, [initialLogEntry]);
    if (witnessProofs.length > 0) {
      allProofs = [...allProofs, ...witnessProofs];
      initialLogEntry[4] = allProofs;
    }
  }
  return {
    did: doc.id!,
    doc,
    meta: {
      versionId: initialLogEntry[0],
      created: initialLogEntry[1],
      updated: initialLogEntry[1],
      ...params
    },
    log: [
      initialLogEntry
    ]
  }
}

export const resolveDID = async (log: DIDLog, options: {
  versionNumber?: number, 
  versionId?: string, 
  versionTime?: Date,
  verificationMethod?: string
} = {}): Promise<{did: string, doc: any, meta: DIDResolutionMeta}> => {
  if (options.verificationMethod && (options.versionNumber || options.versionId)) {
    throw new Error("Cannot specify both verificationMethod and version number/id");
  }
  const resolutionLog = clone(log);
  const protocol = resolutionLog[0][2].method;
  if(protocol !== PROTOCOL) {
    throw new Error(`'${protocol}' protocol unknown.`);
  }
  let doc: any = {};
  let did = '';
  let meta: DIDResolutionMeta = {
    versionId: '',
    created: '',
    updated: '',
    previousLogEntryHash: '',
    scid: '',
    prerotation: false,
    portable: false,
    nextKeyHashes: [],
    deactivated: false,
    updateKeys: [],
    witnesses: [],
    witnessThreshold: 0
  };
  let host = '';
  let i = 0;
  let nextKeyHashes: string[] = [];

  for (const entry of resolutionLog) {
    const [currentVersionId, timestamp, params, data, proof] = entry;
    const [version, entryHash] = currentVersionId.split('-');
    if (parseInt(version) !== i + 1) {
      throw new Error(`version '${version}' in log doesn't match expected '${i + 1}'.`);
    }
    meta.versionId = currentVersionId;
    if (timestamp) {
      // TODO check timestamps make sense
    }
    meta.updated = timestamp;

    // doc patches & proof
    let newDoc;
    if (version === '1') {
      meta.created = timestamp;
      newDoc = data.value;
      host = newDoc.id.split(':').at(-1);
      meta.scid = params.scid;
      meta.portable = params.portable ?? meta.portable;
      meta.updateKeys = params.updateKeys;
      meta.prerotation = params.prerotation === true;
      meta.witnesses = params.witnesses || meta.witnesses;
      meta.witnessThreshold = params.witnessThreshold || meta.witnessThreshold || meta.witnesses.length;
      nextKeyHashes = params.nextKeyHashes ?? [];
      newKeysAreValid(meta.updateKeys, [], nextKeyHashes, false, meta.prerotation === true); 
      const logEntryHash = deriveHash(
        [
          PLACEHOLDER,
          meta.created,
          JSON.parse(JSON.stringify(params).replaceAll(meta.scid, PLACEHOLDER)),
          {value: JSON.parse(JSON.stringify(newDoc).replaceAll(meta.scid, PLACEHOLDER))}
        ]
      );
      meta.previousLogEntryHash = logEntryHash;
      if (!await scidIsFromHash(meta.scid, logEntryHash)) {
        throw new Error(`SCID '${meta.scid}' not derived from logEntryHash '${logEntryHash}'`);
      }
      const verified = await documentStateIsValid(newDoc, proof, meta.updateKeys, meta.witnesses);
      if (!verified) {
        throw new Error(`version ${meta.versionId} failed verification of the proof.`)
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
      if (!meta.portable && newHost !== host) {
        throw new Error("Cannot move DID: portability is disabled");
      } else if (newHost !== host) {
        host = newHost;
      }
      newKeysAreValid(params.updateKeys ?? [], nextKeyHashes, params.nextKeyHashes ?? [], meta.prerotation, params.prerotation === true);
      if (!hashChainValid(`${i+1}-${entryHash}`, entry[0])) {
        throw new Error(`Hash chain broken at '${meta.versionId}'`);
      }
      const verified = await documentStateIsValid(newDoc, proof, meta.updateKeys, meta.witnesses);
      if (!verified) {
        throw new Error(`version ${meta.versionId} failed verification of the proof.`)
      }
      if (params.updateKeys) {
        meta.updateKeys = params.updateKeys;
      }
      if (params.deactivated === true) {
        meta.deactivated = true;
      }
      if (params.prerotation === true) {
        meta.prerotation = true;
      }
      if (params.nextKeyHashes) {
        nextKeyHashes = params.nextKeyHashes;
      }
      if (params.witnesses) {
        meta.witnesses = params.witnesses;
        meta.witnessThreshold = params.witnessThreshold || params.witnesses.length;
      }
    }
    doc = clone(newDoc);
    did = doc.id;

    // Check for matching verification method
    if (options.verificationMethod && findVerificationMethod(doc, options.verificationMethod)) {
      return {did, doc, meta};
    }

    if (options.versionNumber === parseInt(version) || options.versionId === meta.versionId) {
      return {did, doc, meta};
    }
    if (options.versionTime && options.versionTime > new Date(meta.updated)) {
      if (resolutionLog[i+1] && options.versionTime < new Date(resolutionLog[i+1][1])) {
        return {did, doc, meta};
      } else if(!resolutionLog[i+1]) {
        return {did, doc, meta};
      }
    }
    i++;
  }
  if (options.versionTime || options.versionId || options.verificationMethod) {
    throw new Error(`DID with options ${JSON.stringify(options)} not found`);
  }
  return {did, doc, meta};
}

export const updateDID = async (options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}> => {
  const {
    log, updateKeys, context, verificationMethods, services, alsoKnownAs,
    controller, domain, nextKeyHashes, prerotation, witnesses, witnessThreshold
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
  const params = {
    ...(updateKeys ? {updateKeys} : {}),
    ...(prerotation ? {prerotation: true, nextKeyHashes} : {}),
    ...(witnesses || meta.witnesses ? {
      witnesses: witnesses || meta.witnesses,
      witnessThreshold: witnesses ? witnessThreshold || witnesses.length : meta.witnessThreshold
    } : {})
  };
  const [currentVersion] = meta.versionId.split('-');
  const nextVersion = parseInt(currentVersion) + 1;
  meta.updated = createDate(options.updated);
  const patch = jsonpatch.compare(doc, newDoc);
  const logEntry = [
    meta.versionId,
    meta.updated,
    params,
    {patch: clone(patch)},
    [] as DataIntegrityProof[]
  ];
  const logEntryHash = deriveHash(logEntry);
  logEntry[0] = `${nextVersion}-${logEntryHash}`;
  const signedDoc = await options.signer(newDoc, logEntry[0]);
  logEntry[4] = [signedDoc.proof];
  if (meta.witnesses && meta.witnesses.length > 0) {
    const witnessProofs = await collectWitnessProofs(meta.witnesses, [...log, logEntry] as DIDLog);
    if (witnessProofs.length > 0) {
      logEntry[4] = [...logEntry[4], ...witnessProofs];
    }
  }
  return {
    did,
    doc: newDoc,
    meta: {
      ...meta,
      versionId: logEntry[0],
      created: meta.created,
      updated: meta.updated,
      previousLogEntryHash: meta.previousLogEntryHash,
      ...params
    },
    log: [
      ...clone(log),
      clone(logEntry)
    ]
  };
}

export const deactivateDID = async (options: DeactivateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}> => {
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
  const logEntry: DIDLogEntry = [
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
      ...meta,
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
