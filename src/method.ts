import { clone, collectWitnessProofs, createDate, createDIDDoc, createSCID, deriveHash, findVerificationMethod, normalizeVMs } from "./utils";
import { BASE_CONTEXT, METHOD, PLACEHOLDER, PROTOCOL } from './constants';
import { documentStateIsValid, hashChainValid, newKeysAreValid, scidIsFromHash } from './assertions';


export const createDID = async (options: CreateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied')
  }
  debugger;
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
  const initialLogEntry: DIDLogEntry = {
    versionId: PLACEHOLDER,
    versionTime: createdDate,
    parameters: {
      method: PROTOCOL,
      ...params
    },
    state: doc
  };
  const initialLogEntryHash = deriveHash(initialLogEntry);
  params.scid = await createSCID(initialLogEntryHash);
  doc = JSON.parse(JSON.stringify(doc).replaceAll(PLACEHOLDER, params.scid));

  initialLogEntry.versionId = `1-${initialLogEntryHash}`;
  initialLogEntry.parameters = JSON.parse(JSON.stringify(initialLogEntry.parameters).replaceAll(PLACEHOLDER, params.scid));
  initialLogEntry.state = doc;

  const signedDoc = await options.signer(doc, initialLogEntry.versionId);
  let allProofs = [signedDoc.proof];
  initialLogEntry.proof = allProofs;

  if (options.witnesses && options.witnesses.length > 0) {
    const witnessProofs = await collectWitnessProofs(options.witnesses, [initialLogEntry]);
    if (witnessProofs.length > 0) {
      allProofs = [...allProofs, ...witnessProofs];
      initialLogEntry.proof = allProofs;
    }
  }
  return {
    did: doc.id!,
    doc,
    meta: {
      versionId: initialLogEntry.versionId,
      created: initialLogEntry.versionTime,
      updated: initialLogEntry.versionTime,
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
  const protocol = resolutionLog[0].parameters.method;
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
    const { versionId, versionTime, parameters, state, proof } = entry;
    const [version, entryHash] = versionId.split('-');
    if (parseInt(version) !== i + 1) {
      throw new Error(`version '${version}' in log doesn't match expected '${i + 1}'.`);
    }
    meta.versionId = versionId;
    if (versionTime) {
      // TODO check timestamps make sense
    }
    meta.updated = versionTime;

    // doc patches & proof
    let newDoc = state;
    if (version === '1') {
      meta.created = versionTime;
      newDoc = state;
      host = newDoc.id.split(':').at(-1);
      meta.scid = parameters.scid;
      meta.portable = parameters.portable ?? meta.portable;
      meta.updateKeys = parameters.updateKeys;
      meta.prerotation = parameters.prerotation === true;
      meta.witnesses = parameters.witnesses || meta.witnesses;
      meta.witnessThreshold = parameters.witnessThreshold || meta.witnessThreshold || meta.witnesses.length;
      nextKeyHashes = parameters.nextKeyHashes ?? [];
      newKeysAreValid(meta.updateKeys, [], nextKeyHashes, false, meta.prerotation === true); 
      const logEntryHash = deriveHash(
        {
          versionId: PLACEHOLDER,
          versionTime: meta.created,
          parameters: JSON.parse(JSON.stringify(parameters).replaceAll(meta.scid, PLACEHOLDER)),
          state: JSON.parse(JSON.stringify(newDoc).replaceAll(meta.scid, PLACEHOLDER))
        }
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
      if (parameters.prerotation === true && (!parameters.nextKeyHashes || parameters.nextKeyHashes.length === 0)) {
        throw new Error("prerotation enabled without nextKeyHashes");
      }
      const newHost = newDoc.id.split(':').at(-1);
      if (!meta.portable && newHost !== host) {
        throw new Error("Cannot move DID: portability is disabled");
      } else if (newHost !== host) {
        host = newHost;
      }
      newKeysAreValid(parameters.updateKeys ?? [], nextKeyHashes, parameters.nextKeyHashes ?? [], meta.prerotation, parameters.prerotation === true);
      if (!hashChainValid(`${i+1}-${entryHash}`, entry.versionId)) {
        throw new Error(`Hash chain broken at '${meta.versionId}'`);
      }
      const verified = await documentStateIsValid(newDoc, proof, meta.updateKeys, meta.witnesses);
      if (!verified) {
        throw new Error(`version ${meta.versionId} failed verification of the proof.`)
      }
      if (parameters.updateKeys) {
        meta.updateKeys = parameters.updateKeys;
      }
      if (parameters.deactivated === true) {
        meta.deactivated = true;
      }
      if (parameters.prerotation === true) {
        meta.prerotation = true;
      }
      if (parameters.nextKeyHashes) {
        nextKeyHashes = parameters.nextKeyHashes;
      }
      if (parameters.witnesses) {
        meta.witnesses = parameters.witnesses;
        meta.witnessThreshold = parameters.witnessThreshold || parameters.witnesses.length;
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
      if (resolutionLog[i+1] && options.versionTime < new Date(resolutionLog[i+1].versionTime)) {
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
    did = `did:${METHOD}:${domain}:${log[0].parameters.scid}`;
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
  const logEntry: DIDLogEntry = {
    versionId: meta.versionId,
    versionTime: meta.updated,
    parameters: params,
    state: clone(newDoc),
    proof: []
  };
  const logEntryHash = deriveHash(logEntry);
  logEntry.versionId = `${nextVersion}-${logEntryHash}`;
  const signedDoc = await options.signer(newDoc, logEntry.versionId);
  logEntry.proof = [signedDoc.proof];
  const newMeta = {
    ...meta,
    versionId: logEntry.versionId,
    created: meta.created,
    updated: meta.updated,
    previousLogEntryHash: meta.previousLogEntryHash,
    ...params
  };
  if (newMeta.witnesses && newMeta.witnesses.length > 0) {
    const witnessProofs = await collectWitnessProofs(newMeta.witnesses, [...log, logEntry] as DIDLog);
    if (witnessProofs.length > 0) {
      logEntry.proof = [...logEntry.proof, ...witnessProofs];
    }
  }
  return {
    did,
    doc: newDoc,
    meta: newMeta,
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
  const logEntry: DIDLogEntry = {
    versionId: meta.versionId,
    versionTime: meta.updated,
    parameters: {deactivated: true},
    state: clone(newDoc),
    proof: []
  };
  const logEntryHash = deriveHash(logEntry);
  logEntry.versionId = `${nextVersion}-${logEntryHash}`;
  const signedDoc = await options.signer(newDoc, logEntry.versionId);
  logEntry.proof = [signedDoc.proof];
  return {
    did,
    doc: newDoc,
    meta: {
      ...meta,
      versionId: logEntry.versionId,
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
