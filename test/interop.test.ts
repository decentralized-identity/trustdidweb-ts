import { describe, expect, test } from "bun:test";
import { resolveDID } from "../src/method";

describe("did:tdw interoperability tests", async () => {
  test.skip("anywhy.ca", async () => {
    const did = "did:tdw:QmRyZ5pcm12CmMs4UhuN3h3Vr7Z7qRqHkxjNzUQpygPe25:anywhy.ca";
    const {did: resolvedDID, meta} = await resolveDID(did);
    expect(resolvedDID).toBe(did);
    expect(meta.versionId).toBe("3-QmYKJo2xvahkwKFKzEybDMzSWGYcPVsX2eGYZTYqY678iK");
    expect(meta.nextKeyHashes.length).toBeGreaterThan(0);
    expect(meta.prerotation).toBe(true);
    expect(meta.portable).toBe(false);
  })

  test("gist", async () => {
    const did = "did:tdw:QmbnQXj7DhWFrmgjDPKZCybn8fkKW7Wze57SQHpwsSQ7NZ:gist.githubusercontent.com:brianorwhatever:9c4633d18eb644f7a47f93a802691626:raw";
    const {did: resolvedDID, meta} = await resolveDID(did);
    expect(resolvedDID).toBe(did);
    expect(meta.prerotation).toBe(false);
    expect(meta.portable).toBe(false);
  })
});
