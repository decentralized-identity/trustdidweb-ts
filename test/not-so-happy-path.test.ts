import { expect, test } from "bun:test";
import { readLogFromDisk, writeLogToDisk } from "./utils";
import { createDID, resolveDID, updateDID } from "../src/method";
import { createSigner, generateEd25519VerificationMethod } from "../src/cryptography";

test("Update with wrong key fails resolution", async () => {
  const authKey = await generateEd25519VerificationMethod('authentication');
  const assertionKey = await generateEd25519VerificationMethod('assertionMethod');
  const {doc: newDoc, log: newLog} = await createDID({
    domain: 'example.com',
    updateKeys: [authKey.publicKeyMultibase!],
    signer: createSigner(authKey as any),
    verificationMethods: [
      authKey as any,
      assertionKey,
    ]});
    
  let err;
  try {
    const result =
      await updateDID({
        log: newLog,
        signer: createSigner(assertionKey as any),
        context: newDoc['@context'],
        verificationMethods: [
          await generateEd25519VerificationMethod('authentication'),
          await generateEd25519VerificationMethod('assertionMethod'),
        ]
      });

      // TODO
      // DONT LET BAD KEYS SIGN
      writeLogToDisk('./test/fixtures/not-authorized.log', result.log);
  } catch(e) {
    err = e;
  }
  
  const badLog = readLogFromDisk('./test/fixtures/not-authorized.log');
  let result;
  try {
    result = await resolveDID(badLog);
  } catch(e: any) {
    err = e;
  }

  expect(result).toBeUndefined();
  expect(err.message).toContain('is not authorized to update.')
});