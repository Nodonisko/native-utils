// secp256k1 group order N (same as noble/secp256k1)
export const N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Convert bigint to 32-byte Uint8Array (big-endian)
 */
export function bigintToBytes(num: bigint): Uint8Array {
  if (num < 0n) {
    throw new Error('Private key must be positive');
  }
  if (num === 0n) {
    throw new Error('Private key cannot be zero');
  }
  if (num >= N) {
    throw new Error('Private key must be less than the secp256k1 curve order');
  }

  const bytes = new Uint8Array(32);
  let n = num;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(n & 0xffn);
    n = n >> 8n;
  }
  return bytes;
}

/**
 * Convert Uint8Array to ArrayBuffer (create a new one to avoid SharedArrayBuffer issues)
 */
export function uint8ArrayToArrayBuffer(uint8Array: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(uint8Array.length);
  const view = new Uint8Array(buffer);
  view.set(uint8Array);
  return buffer;
}

/**
 * Convert ArrayBuffer to Uint8Array
 */
export function arrayBufferToUint8Array(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer);
}

/**
 * Convert number array to Uint8Array
 */
export function numberArrayToUint8Array(arr: number[]): Uint8Array {
  return new Uint8Array(arr);
}
