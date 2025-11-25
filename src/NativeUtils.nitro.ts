import type { HybridObject } from 'react-native-nitro-modules';

export interface NativeUtils
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  multiply(a: number, b: number): number;
  toPublicKey(privateKey: string, isCompressed: boolean): ArrayBuffer;
  toPublicKeyFromBytes(
    privateKey: ArrayBuffer,
    isCompressed: boolean,
  ): ArrayBuffer;
  getPublicKeyEd25519(privateKey: string): ArrayBuffer;
  getPublicKeyEd25519FromBytes(privateKey: ArrayBuffer): ArrayBuffer;
  keccak256FromBytes(data: ArrayBuffer): ArrayBuffer;
  pubToAddress(pubKey: ArrayBuffer, sanitize: boolean): ArrayBuffer;
  hmacSha512(key: ArrayBuffer, data: ArrayBuffer): ArrayBuffer;
}
