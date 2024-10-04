import { resolveDID } from '../method';
import { getFileUrl } from '../utils';

export const getLatestDIDDoc = async ({params: {id}}: {params: {id: string;};}) => {
  try {
    const url = getFileUrl(id);
    const didLog = await (await fetch(url)).text();
    const logEntries: DIDLog = didLog.trim().split('\n').map(l => JSON.parse(l));
    const {did, doc, meta} = await resolveDID(logEntries);
    return {doc, meta};
  } catch (e) {
    console.error(e)
    throw new Error(`Failed to resolve DID`);
  }
}

export const getLogFileForSCID = async ({params: {scid}}: {params: {scid: string}}) => {
  return await Bun.file(`./src/routes/${scid}/did.jsonl`).text();
}

export const getLogFileForBase = async () => {
  return await Bun.file(`./src/routes/.well-known/did.jsonl`).text();
}