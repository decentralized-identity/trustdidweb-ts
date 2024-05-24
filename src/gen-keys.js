import fs from 'node:fs';
import {generate as generateEd25519} from '@digitalbazaar/ed25519-multikey';
import { base58btc } from "multiformats/bases/base58"

export const genKeys = async (count) => {
  let i = 0;
  const keys = [];
  while(i < count) {
    // const {publicKeyMultibase, secretKeyMultibase} = await generateEd25519();
    const {publicKeyMultibase, secretKeyMultibase} = await generateEd25519();
    keys.push({publicKeyMultibase, secretKeyMultibase});
    i++;
  }
  console.log(keys);
  // fs.writeFileSync('./in/keys.json', JSON.stringify(keys, null, 2))
}

await genKeys(2);