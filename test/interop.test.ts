import { describe, expect, test } from "bun:test";
import { resolveDID } from "../src";

describe("did:tdw normative tests", async () => {
  test("anywhy.ca", async () => {
    const didLog: DIDLog = [
      ["1-Qmabn3Tj2Bs5RMtbBuKPGwaAzPZbm9amhSzVxPw3HpZJqw", "2024-07-31T16:46:31Z", {"prerotation": false, "updateKeys": ["z6Mku46DLkSH6kHudmyjpiPktTfe7a9tcqipnFnLdSLnFiHx"], "method": "did:tdw:0.3", "scid": "QmbnhbtbN9NLCSL9TGpDLVChPd9KUw6QEJqQ9XWn3ZZ9qT"}, {"value": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], "id": "did:tdw:QmbnhbtbN9NLCSL9TGpDLVChPd9KUw6QEJqQ9XWn3ZZ9qT:anywhy.ca"}}, [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6Mku46DLkSH6kHudmyjpiPktTfe7a9tcqipnFnLdSLnFiHx#z6Mku46DLkSH6kHudmyjpiPktTfe7a9tcqipnFnLdSLnFiHx", "created": "2024-07-31T16:46:31Z", "proofPurpose": "authentication", "challenge": "1-Qmabn3Tj2Bs5RMtbBuKPGwaAzPZbm9amhSzVxPw3HpZJqw", "proofValue": "z5YDUr8bhCwWBn64rrWXoNCVRwS25rrT96G8DW1g8deJRhTy6LgBkL6DAxJNUhLHhx6gTEdV2abdDFHVEcajTotzh"}]],
      ["2-QmYDqCcA5HT18AEAchLwfP9xkab3Kz1YL9VPYNqXsAJ358", "2024-07-31T16:46:32Z", {}, {"patch": [{"op": "add", "path": "/authentication", "value": ["did:tdw:QmbnhbtbN9NLCSL9TGpDLVChPd9KUw6QEJqQ9XWn3ZZ9qT:anywhy.ca#z6MkiP9rSWJivm6nFf7YH2tYtfqyEUoKn5P6G5VC3NdCoTpZ"]}, {"op": "add", "path": "/verificationMethod", "value": [{"id": "did:tdw:QmbnhbtbN9NLCSL9TGpDLVChPd9KUw6QEJqQ9XWn3ZZ9qT:anywhy.ca#z6MkiP9rSWJivm6nFf7YH2tYtfqyEUoKn5P6G5VC3NdCoTpZ", "controller": "did:tdw:QmbnhbtbN9NLCSL9TGpDLVChPd9KUw6QEJqQ9XWn3ZZ9qT:anywhy.ca", "type": "Multikey", "publicKeyMultibase": "z6MkiP9rSWJivm6nFf7YH2tYtfqyEUoKn5P6G5VC3NdCoTpZ"}]}, {"op": "add", "path": "/service", "value": [{"id": "did:tdw:QmbnhbtbN9NLCSL9TGpDLVChPd9KUw6QEJqQ9XWn3ZZ9qT:anywhy.ca#domain", "type": "LinkedDomains", "serviceEndpoint": "https://anywhy.ca"}, {"id": "did:tdw:QmbnhbtbN9NLCSL9TGpDLVChPd9KUw6QEJqQ9XWn3ZZ9qT:anywhy.ca#whois", "type": "LinkedVerifiablePresentation", "serviceEndpoint": "https://anywhy.ca/.well-known/whois.vc"}]}, {"op": "add", "path": "/assertionMethod", "value": ["did:tdw:QmbnhbtbN9NLCSL9TGpDLVChPd9KUw6QEJqQ9XWn3ZZ9qT:anywhy.ca#z6MkiP9rSWJivm6nFf7YH2tYtfqyEUoKn5P6G5VC3NdCoTpZ"]}, {"op": "add", "path": "/@context/2", "value": "https://identity.foundation/.well-known/did-configuration/v1"}, {"op": "add", "path": "/@context/3", "value": "https://identity.foundation/linked-vp/contexts/v1"}]}, [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6Mku46DLkSH6kHudmyjpiPktTfe7a9tcqipnFnLdSLnFiHx#z6Mku46DLkSH6kHudmyjpiPktTfe7a9tcqipnFnLdSLnFiHx", "created": "2024-07-31T16:46:32Z", "proofPurpose": "authentication", "challenge": "2-QmYDqCcA5HT18AEAchLwfP9xkab3Kz1YL9VPYNqXsAJ358", "proofValue": "zghVCLhCwHZaBZrBtqJLLCedwV4cGuokKtWVwwXoYFFZcE48gsQPQq5HZ8qmvacqCaeKtMFJ2oXcBqHmpqkXJeNj"}]]
    ];
    
    const res = await resolveDID(didLog);

    expect(res.did).toBe("did:tdw:QmbnhbtbN9NLCSL9TGpDLVChPd9KUw6QEJqQ9XWn3ZZ9qT:anywhy.ca");
    expect(res.meta.versionId).toBe("2-QmYDqCcA5HT18AEAchLwfP9xkab3Kz1YL9VPYNqXsAJ358");
    expect(res.meta.prerotation).toBe(false);
    expect(res.meta.portable).toBe(false);
  })
});
