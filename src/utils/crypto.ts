/// <reference lib="dom" />
import { config } from '../config';

function stringToUint8Array(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

function arrayBufferToHex(buffer: ArrayBufferLike | Uint8Array): string {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(view)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function createHash(data: string): Promise<Uint8Array> {
  if (config.isBrowser) {
    const msgUint8 = stringToUint8Array(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    return new Uint8Array(hashBuffer);
  } else {
    const { createHash } = await import('node:crypto');
    return new Uint8Array(createHash('sha256').update(data).digest());
  }
}

export async function createHashHex(data: string): Promise<string> {
  const hash = await createHash(data);
  const view = new Uint8Array(hash.buffer);
  return arrayBufferToHex(view);
} 