import fs from 'node:fs';
import * as base58btc from '@interop/base58-universal'
import { canonicalize } from 'json-canonicalize';
import { nanoid } from 'nanoid';
import { sha256 } from 'multiformats/hashes/sha2'

export const readLogFromDisk = (path: string): DIDLog => {
  return fs.readFileSync(path, 'utf8').trim().split('\n').map(l => JSON.parse(l));
}

export const writeLogToDisk = (path: string, log: DIDLog) => {
  fs.writeFileSync(path, JSON.stringify(log.shift()) + '\n');
  for (const entry of log) {
    fs.appendFileSync(path, JSON.stringify(entry) + '\n');
  }
}

export const clone = (input: any) => JSON.parse(JSON.stringify(input));

export const getFileUrl = (id: string) => {
  if (!id.startsWith('did:tdw:')) {
    throw new Error(`${id} is not a valid did:tdw identifier`);
  }
  
  const parts = id.split(':');
  if (parts.length < 4) {
    throw new Error(`${id} is not a valid did:tdw identifier`);
  }
  
  const domain = parts.slice(3).join(':');
  const protocol = domain.includes('localhost') ? 'http' : 'https';
  
  if (domain.includes('/')) {
    return `${protocol}://${domain}/did.jsonl`;
  }
  return `${protocol}://${domain}/.well-known/did.jsonl`;
}

export const createDate = (created?: Date | string) => new Date(created ?? Date.now()).toISOString().slice(0,-5)+'Z';

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export const createSCID = async (logEntryHash: string): Promise<string> => {
  return logEntryHash;
}

export const deriveHash = (input: any): string => {
  const data = canonicalize(input);
  const encoder = new TextEncoder();
  return base58btc.encode((sha256.digest(encoder.encode(data)) as any).bytes);
}

export const createDIDDoc = async (options: CreateDIDInterface): Promise<{doc: DIDDoc}> => {
  const {controller} = options;
  const {all} = normalizeVMs(options.verificationMethods, controller);
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

export const createVMID = (vm: VerificationMethod, did: string | null) => {
  return `${did ?? ''}#${vm.publicKeyMultibase?.slice(-8) || nanoid(8)}`
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

export const collectWitnessProofs = async (witnesses: string[], log: DIDLog): Promise<DataIntegrityProof[]> => {
  const proofs: DataIntegrityProof[] = [];

  const timeout = (ms: number) => new Promise((_, reject) => 
    setTimeout(() => reject(new Error('Request timed out')), ms)
  );

  const collectProof = async (witness: string): Promise<void> => {
    const parts = witness.split(':');
    if (parts.length < 4) {
      throw new Error(`${witness} is not a valid did:tdw identifier`);
    }
    
    const domain = parts.slice(3).join(':');
    const protocol = domain.includes('localhost') ? 'http' : 'https';
    const witnessUrl = `${protocol}://${domain}/witness`;
    try {
      const response: any = await Promise.race([
        fetch(`${witnessUrl}/witness`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ log }),
        }),
        timeout(10000) // 10 second timeout
      ]);

      if (response.ok) {
        const data = await response.json();
        if (data.proof) {
          proofs.push(data.proof);
        } else {
          console.warn(`Witness ${witnessUrl} did not provide a valid proof`);
        }
      } else {
        console.warn(`Witness ${witnessUrl} responded with status: ${response.status}`);
      }
    } catch (error: any) {
      if (error.message === 'Request timed out') {
        console.error(`Request to witness ${witnessUrl} timed out`);
      } else {
        console.error(`Error collecting proof from witness ${witnessUrl}:`, error);
      }
    }
  };

  // Collect proofs from all witnesses concurrently
  await Promise.all(witnesses.map(collectProof));

  return proofs;
};