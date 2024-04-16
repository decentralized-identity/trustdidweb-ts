export const clone = (input: any) => JSON.parse(JSON.stringify(input));

export const createDate = (created?: Date) => new Date(created ?? Date.now()).toISOString().slice(0,-5)+'Z';

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
}
