export interface DIDResolutionMeta {
  versionId: string;
  created: string;
  updated: string;
  previousLogEntryHash?: string;
  updateKeys: string[];
  scid: string;
  prerotation: boolean;
  portable: boolean;
  nextKeyHashes: string[];
  deactivated: boolean;
  witness?: WitnessParameter | undefined | null;
}

export interface DIDDoc {
  "@context"?: string | string[] | object | object[];
  id?: string;
  controller?: string | string[];
  alsoKnownAs?: string[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  capabilityInvocation?: string[];
  capabilityDelegation?: string[];
  verificationMethod?: VerificationMethod[];
  service?: ServiceEndpoint[];
}

export interface DataIntegrityProof {
  id?: string;
  type: string;
  cryptosuite: string;
  verificationMethod: string;
  created: string;
  proofValue: string;
  proofPurpose: string;
}

interface WitnessParameter {
  threshold: number;
  witnesses: WitnessEntry[];
}

interface WitnessEntry {
  id: string;  // did:key DID
  weight: number;
}

interface WitnessProofFileEntry {
  versionId: string;
  proof: DataIntegrityProof[];
}

export interface DIDLogEntry {
  versionId: string;
  versionTime: string;
  parameters: {
    method?: string;
    scid?: string;
    updateKeys?: string[];
    nextKeyHashes?: string[];
    portable?: boolean;
    witness?: WitnessParameter | null;
    deactivated?: boolean;
  };
  state: DIDDoc;
  proof?: DataIntegrityProof[];
}

export type DIDLog = DIDLogEntry[];

export interface ServiceEndpoint {
  id?: string;
  type: string | string[];
  serviceEndpoint?: string | string[] | any;
}

export interface VerificationMethod {
  id?: string;
  type: 'Multikey';
  purpose?: 'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation' | 'capabilityDelegation';
  controller?: string;
  publicKeyJWK?: any;
  publicKeyMultibase?: string;
  secretKeyMultibase?: string;
  use?: string;
}

export interface CreateDIDInterface {
  domain: string;
  updateKeys: string[];
  signer: (doc: any) => Promise<{proof: any}>;
  controller?: string;
  context?: string | string[];
  verificationMethods?: VerificationMethod[];
  created?: Date;
  nextKeyHashes?: string[];
  portable?: boolean;
  witness?: WitnessParameter | null;
}

export interface SignDIDDocInterface {
  document: any;
  proof: any;
  verificationMethod: VerificationMethod
}

export interface UpdateDIDInterface {
  log: DIDLog;
  signer: (doc: any) => Promise<{proof: any}>;
  updateKeys?: string[];
  context?: string[];
  controller?: string[];
  verificationMethods?: VerificationMethod[];
  services?: ServiceEndpoint[];
  alsoKnownAs?: string[];
  domain?: string;
  updated?: Date | string;
  deactivated?: boolean;
  nextKeyHashes?: string[];
  witness?: WitnessParameter | undefined | null;
  witnessProofs?: WitnessProofFileEntry[];
}

export interface DeactivateDIDInterface {
  log: DIDLog;
  signer: (doc: any) => Promise<{proof: any}>;
  updateKeys?: string[];
}

interface ResolutionOptions {
  versionNumber?: number;
  versionId?: string;
  versionTime?: Date;
  verificationMethod?: string;
  witnessProofs?: WitnessProofFileEntry[];
}
