import { NitroModules } from 'react-native-nitro-modules';
import type { NativeUtils } from './NativeUtils.nitro';
import {
  bigintToBytes,
  uint8ArrayToArrayBuffer,
  arrayBufferToUint8Array,
} from './utils';

const NativeUtilsHybridObject =
  NitroModules.createHybridObject<NativeUtils>('NativeUtils');

export function multiply(a: number, b: number): number {
  return NativeUtilsHybridObject.multiply(a, b);
}

/** Uint8Array alias for compatibility */
export type Bytes = Uint8Array;
/** Hex-encoded string or Uint8Array. */
export type Hex = Bytes | string;
/** Private key can be hex string, Uint8Array, or bigint. */
export type PrivKey = Hex | bigint;

/**
 * Generate a public key from a private key using the secp256k1 elliptic curve.
 * This is a fast native implementation that matches the noble/secp256k1 API.
 *
 * @param privateKey - The private key as a hex string, Uint8Array, or bigint
 * @param isCompressed - Whether to return compressed (33 bytes) or uncompressed (65 bytes) public key
 * @returns Uint8Array containing the public key bytes
 */
export function getPublicKey(
  privateKey: PrivKey,
  isCompressed: boolean = true,
): Uint8Array {
  let result: ArrayBuffer;

  if (typeof privateKey === 'string') {
    // Use the string version (C++ will handle hex validation)
    result = NativeUtilsHybridObject.toPublicKey(privateKey, isCompressed);
  } else if (typeof privateKey === 'bigint') {
    // Convert bigint to bytes (basic validation here, detailed validation in C++)
    const privateKeyBytes = bigintToBytes(privateKey);
    const privateKeyBuffer = uint8ArrayToArrayBuffer(privateKeyBytes);
    result = NativeUtilsHybridObject.toPublicKeyFromBytes(
      privateKeyBuffer,
      isCompressed,
    );
  } else if (privateKey instanceof Uint8Array) {
    // Convert Uint8Array to ArrayBuffer (C++ will handle length and scalar validation)
    if (privateKey.length !== 32) {
      throw new Error('Uint8Array expected');
    }
    const privateKeyBuffer = uint8ArrayToArrayBuffer(privateKey);
    result = NativeUtilsHybridObject.toPublicKeyFromBytes(
      privateKeyBuffer,
      isCompressed,
    );
  } else {
    throw new Error('Private key must be a hex string, Uint8Array, or bigint');
  }

  // Convert result from ArrayBuffer to Uint8Array to match noble's API
  return arrayBufferToUint8Array(result);
}
