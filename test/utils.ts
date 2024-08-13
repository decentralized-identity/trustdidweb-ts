import fs from 'node:fs';
import { deriveHash } from '../src/utils';

export const readLogFromDisk = (path: string): DIDLog => {
  return fs.readFileSync(path, 'utf8').trim().split('\n').map(l => JSON.parse(l));
}

export const writeLogToDisk = (path: string, log: DIDLog) => {
  fs.writeFileSync(path, JSON.stringify(log.shift()) + '\n');
  for (const entry of log) {
    fs.appendFileSync(path, JSON.stringify(entry) + '\n');
  }
}

export function createMockDIDLog(entries: Partial<DIDLogEntry>[]): DIDLog {
  return entries.map((entry, index) => {
    const versionNumber = index + 1;
    const mockEntry: DIDLogEntry = [
      `${versionNumber}-${deriveHash(entry)}`,
      entry[1] || new Date().toISOString(),
      entry[2] || {},
      entry[3] || { value: {} },
      entry[4] || []
    ];
    return mockEntry;
  });
}