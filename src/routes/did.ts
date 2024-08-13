import { resolveDID } from '../method';
import { getFileUrl } from '../utils';

export const getLatestDIDDoc = async ({params: {id}, set}: {params: {id: string;}; set: any;}) => {
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

export const getLogFile = ({params: {scid}}: {params: {scid: string}}) => {
  return Bun.file(`./test/logs/${scid}/did.jsonl`);
}