import { NitroModules } from 'react-native-nitro-modules';
import type { NativeUtils } from './NativeUtils.nitro';
import {
  bigintPrivateKeyToBytes,
  uint8ArrayToArrayBuffer,
  arrayBufferToUint8Array,
  numberArrayToUint8Array,
} from './utils';

const NativeUtilsHybridObject =
  NitroModules.createHybridObject<NativeUtils>('NativeUtils');

export function multiply(a: number, b: number): number {
  return NativeUtilsHybridObject.multiply(a, b);
}

/** Uint8Array of private key bytes. */
export type BytesPrivateKey = Uint8Array;
/** Hex-encoded string of private key. */
export type HexPrivateKey = string;
/** Private key can be hex string, bytes, or bigint. */
export type PrivateKey = HexPrivateKey | BytesPrivateKey | bigint;

/**
 * Generate a public key from a private key using the secp256k1 elliptic curve.
 * This is a fast native implementation that matches the noble/secp256k1 API.
 *
 * @param privateKey - The private key as a hex string, Uint8Array, or bigint
 * @param isCompressed - Whether to return compressed (33 bytes) or uncompressed (65 bytes) public key
 * @returns Uint8Array containing the public key bytes
 */
export function getPublicKey(
  privateKey: PrivateKey,
  isCompressed: boolean = true,
): Uint8Array {
  let result: ArrayBuffer;

  if (typeof privateKey === 'string') {
    // Use the string version (C++ will handle hex validation)
    result = NativeUtilsHybridObject.toPublicKey(privateKey, isCompressed);
  } else if (typeof privateKey === 'bigint') {
    // Convert bigint to bytes (basic validation here, detailed validation in C++)
    const privateKeyBytes = bigintPrivateKeyToBytes(privateKey);
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

/**
 * Compute Keccak-256 hash using native implementation.
 * 100% compatible with @noble/hashes keccak_256 API.
 * Accepts multiple input types for maximum flexibility.
 *
 * @param data - The data to hash as string (UTF-8), number[], ArrayBuffer, or Uint8Array
 * @returns Uint8Array containing the 32-byte Keccak-256 hash
 */
export function keccak256(
  data: string | number[] | ArrayBuffer | Uint8Array,
): Uint8Array {
  let result: ArrayBuffer;

  if (typeof data === 'string') {
    // Match noble's behavior: treat string as UTF-8 text, not hex
    const encoder = new TextEncoder();
    const bytes = encoder.encode(data);
    const buffer = uint8ArrayToArrayBuffer(bytes);
    result = NativeUtilsHybridObject.keccak256FromBytes(buffer);
  } else if (Array.isArray(data)) {
    // Convert number array to Uint8Array, then to ArrayBuffer
    const bytes = numberArrayToUint8Array(data);
    const buffer = uint8ArrayToArrayBuffer(bytes);
    result = NativeUtilsHybridObject.keccak256FromBytes(buffer);
  } else if (data instanceof ArrayBuffer) {
    // Use ArrayBuffer directly
    result = NativeUtilsHybridObject.keccak256FromBytes(data);
  } else if (data instanceof Uint8Array) {
    // Convert Uint8Array to ArrayBuffer
    const buffer = uint8ArrayToArrayBuffer(data);
    result = NativeUtilsHybridObject.keccak256FromBytes(buffer);
  } else {
    throw new Error(
      'Data must be a string, number[], ArrayBuffer, or Uint8Array',
    );
  }

  // Convert result from ArrayBuffer to Uint8Array to match common crypto library APIs
  return arrayBufferToUint8Array(result);
}

/**
 * Returns the ethereum address of a given public key using native C++ implementation.
 * Accepts "Ethereum public keys" and SEC1 encoded keys.
 * @param pubKey The two points of an uncompressed key, unless sanitize is enabled
 * @param sanitize Accept public keys in other formats
 * @returns Uint8Array containing the 20-byte Ethereum address
 */
export function pubToAddress(
  pubKey: Uint8Array,
  sanitize: boolean = false,
): Uint8Array {
  const pubKeyBuffer = uint8ArrayToArrayBuffer(pubKey);

  const result = NativeUtilsHybridObject.pubToAddress(pubKeyBuffer, sanitize);

  return arrayBufferToUint8Array(result);
}

/**
 * Compute HMAC-SHA512 using native implementation for better performance.
 *
 * @param key - The HMAC key as Uint8Array
 * @param data - The data to authenticate as Uint8Array
 * @returns Uint8Array containing the 64-byte HMAC-SHA512 result
 */
export function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  const keyBuffer = uint8ArrayToArrayBuffer(key);
  const dataBuffer = uint8ArrayToArrayBuffer(data);

  const result = NativeUtilsHybridObject.hmacSha512(keyBuffer, dataBuffer);

  return arrayBufferToUint8Array(result);
}

/**
 * Generate an Ed25519 public key from a private key using native implementation.
 * This is a fast native implementation that matches the noble/curves ed25519 API.
 *
 * @param privateKey - The 32-byte Ed25519 private key as Uint8Array or hex string
 * @param _compressed - Ignored parameter for API compatibility (Ed25519 keys have no compressed form)
 * @returns Uint8Array containing 32-byte Ed25519 public key
 */
export function getPublicKeyEd25519(
  privateKey: BytesPrivateKey | HexPrivateKey,
  _compressed?: boolean,
): Uint8Array {
  let result: ArrayBuffer;

  if (typeof privateKey === 'string') {
    // 64 characters = 32 bytes
    if (privateKey.length !== 64) {
      throw new Error(
        'Ed25519 private key must be 32 bytes (64 hex characters)',
      );
    }

    result = NativeUtilsHybridObject.getPublicKeyEd25519(privateKey);
  } else if (privateKey instanceof Uint8Array) {
    if (privateKey.length !== 32) {
      throw new Error('Ed25519 private key must be 32 bytes');
    }

    const privateKeyBuffer = uint8ArrayToArrayBuffer(privateKey);

    result =
      NativeUtilsHybridObject.getPublicKeyEd25519FromBytes(privateKeyBuffer);
  } else {
    throw new Error('Ed25519 private key must be a hex string or Uint8Array');
  }

  return arrayBufferToUint8Array(result);
}
