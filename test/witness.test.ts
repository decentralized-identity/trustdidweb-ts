import { beforeAll, describe, expect, test } from "bun:test";
import { createDID, resolveDID, updateDID } from "../src/method";
import { createSigner, generateEd25519VerificationMethod } from "../src/cryptography";

let WITNESS_SCID = "";
const WITNESS_SERVER_URL = "http://localhost:8000"; // Update this to match your witness server URL
const WITNESS_DOMAIN = WITNESS_SERVER_URL.split('//')[1].replace(':', '%3A');

const getWitnessDID = async () => {
  try {
    const response = await fetch(`${WITNESS_SERVER_URL}/.well-known/did.jsonl`);
    return response.ok && (await response.json());
  } catch (error) {
    return false;
  }
}

const isWitnessServerRunning = async () => {
  try {
    const response = await fetch(`${WITNESS_SERVER_URL}/health`);
    return response.ok;
  } catch (error) {
    return false;
  }
};

const runWitnessTests = async () => {
  const serverRunning = await isWitnessServerRunning();
  
  if (!serverRunning) {
    describe("Witness functionality", () => {
      test.skip("Witness server is not running", () => {
        // This test will be skipped and shown in the test output
      });
    });
    return;
  }

  describe("Witness functionality", () => {
    let authKey: VerificationMethod;
    let initialDID: { did: string; doc: any; meta: any; log: DIDLog };

    beforeAll(async () => {
      authKey = await generateEd25519VerificationMethod('authentication');
      const didLog = await getWitnessDID();
      const {did, meta} = await resolveDID([didLog] as DIDLog);
      WITNESS_SCID = meta.scid;
      console.log(`Witness DID ${did} found`);
    });

    test("Create DID with witness", async () => {
      const domain = WITNESS_SERVER_URL.split('//')[1].replace(':', '%3A');
      initialDID = await createDID({
        domain,
        signer: createSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: [authKey],
        witnesses: [`did:tdw:${WITNESS_SCID}:${WITNESS_DOMAIN}`],
        witnessThreshold: 1
      });
      const resolved = await resolveDID(initialDID.log);

      expect(resolved.did).toBe(initialDID.did);
      expect(initialDID.meta.witnesses).toHaveLength(1);
      expect(initialDID.meta.witnessThreshold).toBe(1);
      expect(initialDID.log[0][4]).toHaveLength(2); // Controller proof + witness proof
    });

    test("Update DID with witness", async () => {
      const newAuthKey = await generateEd25519VerificationMethod('authentication');
      const updatedDID = await updateDID({
        log: initialDID.log,
        signer: createSigner(authKey),
        updateKeys: [newAuthKey.publicKeyMultibase!],
        verificationMethods: [newAuthKey],
      });

      expect(updatedDID.meta.witnesses).toHaveLength(1);
      expect(updatedDID.meta.witnessThreshold).toBe(1);
      expect(updatedDID.log[updatedDID.log.length - 1][4]).toHaveLength(2); // Controller proof + witness proof
    });

    test("Witness signing with environment variable key", async () => {
      if (!process.env.WITNESS_PRIVATE_KEY) {
        test.skip("WITNESS_PRIVATE_KEY environment variable not set", () => {});
        return;
      }

      const testDID = await createDID({
        domain: 'example.com',
        signer: createSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: [authKey],
        witnesses: [`did:tdw:${WITNESS_SERVER_URL.split('//')[1]}`],
        witnessThreshold: 1
      });

      const response = await fetch(`${WITNESS_SERVER_URL}/witness`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ log: testDID.log }),
      });

      expect(response.ok).toBe(true);

      const data: any = await response.json();
      expect(data.proof).toBeDefined();
      expect(data.proof.type).toBe('DataIntegrityProof');
      expect(data.proof.cryptosuite).toBe('eddsa-jcs-2022');
      expect(data.proof.proofPurpose).toBe('authentication');
    });
  });
};

runWitnessTests();