import { describe, expect, test } from "bun:test";
import { resolveDID } from "../src/method";

describe("did:tdw interoperability tests", async () => {
  test("anywhy.ca", async () => {
    const did = "did:tdw:QmRyZ5pcm12CmMs4UhuN3h3Vr7Z7qRqHkxjNzUQpygPe25:anywhy.ca";

    const {did: resolvedDID, meta} = await resolveDID(did);
    
    expect(resolvedDID).toBe(did);
    expect(meta.versionId).toBe("3-QmYKJo2xvahkwKFKzEybDMzSWGYcPVsX2eGYZTYqY678iK");
    expect(meta.prerotation).toBe(true);
    expect(meta.portable).toBe(false);
  })
});
