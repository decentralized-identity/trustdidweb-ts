import { deriveHash } from '../src/utils';

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
