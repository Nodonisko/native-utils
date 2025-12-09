import { verify, getPublicKey } from '@metamask/native-utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import type { TestResult } from '../testUtils';
import { hexToUint8Array } from '../testUtils';
import ecdsaVectors from '../vectors/secp256k1-ecdsa.json';
import wycheproofVectors from '../vectors/wycheproof-ecdsa-secp256k1.json';

// Type definitions for the vector files
interface ECDSAValidVector {
  description?: string;
  d: string;
  m: string;
  signature: string;
}

interface ECDSAInvalidVerifyVector {
  description: string;
  exception?: string;
  Q: string;
  m: string;
  signature: string;
  strict?: boolean;
}

interface ECDSAVectors {
  valid: ECDSAValidVector[];
  invalid: {
    sign: unknown[];
    verify: ECDSAInvalidVerifyVector[];
  };
  extraEntropy: unknown[];
}

interface WycheproofTest {
  tcId: number;
  comment: string;
  flags: string[];
  msg: string;
  sig: string;
  result: 'valid' | 'invalid' | 'acceptable';
}

interface WycheproofTestGroup {
  type: string;
  publicKey: {
    type: string;
    curve: string;
    keySize: number;
    uncompressed: string;
    wx: string;
    wy: string;
  };
  publicKeyDer: string;
  publicKeyPem: string;
  sha: string;
  tests: WycheproofTest[];
}

interface WycheproofVectors {
  algorithm: string;
  schema: string;
  generatorVersion: string;
  numberOfTests: number;
  header: string[];
  notes: Record<string, unknown>;
  testGroups: WycheproofTestGroup[];
}

// Helper to parse DER signature to compact format (r || s) with STRICT DER validation
// This rejects BER encoding and other malformed signatures
function parseDERSignature(derHex: string): Uint8Array | null {
  try {
    const der = hexToUint8Array(derHex);
    let pos = 0;

    // Check SEQUENCE tag (0x30)
    if (der.length < 2 || der[pos] !== 0x30) return null;
    pos++;

    // Read sequence length - MUST be short form for valid ECDSA sigs (length < 128)
    const seqLen = der[pos]!;
    pos++;

    // Reject long form length encoding (BER) - DER requires short form when possible
    // This prevents potential parsing ambiguities and improves security
    if (seqLen & 0x80) {
      return null; // Long form length not allowed for ECDSA signatures
    }

    // Verify sequence length matches remaining data
    if (seqLen !== der.length - pos) return null;

    // Helper to parse a DER INTEGER with strict validation
    const parseInteger = (): Uint8Array | null => {
      if (pos >= der.length || der[pos] !== 0x02) return null;
      pos++;

      if (pos >= der.length) return null;
      const len = der[pos]!;
      pos++;

      // Length must be short form
      if (len & 0x80) return null;
      if (len === 0) return null; // Zero-length integer not allowed
      if (pos + len > der.length) return null;

      const intBytes = der.slice(pos, pos + len);
      pos += len;

      // Validate DER integer encoding:
      // 1. No unnecessary leading zeros (except for the sign bit case)
      // 2. Must be positive (high bit of first content byte must be 0, or there's a leading 0x00)

      if (intBytes.length > 1) {
        // Check for unnecessary leading zero
        if (intBytes[0] === 0x00 && (intBytes[1]! & 0x80) === 0) {
          return null; // Unnecessary leading zero
        }
      }

      // Check for negative integer (high bit set without leading zero)
      if (intBytes[0]! & 0x80) {
        return null; // Negative integer not allowed
      }

      // Remove valid leading zero (used for positive numbers with high bit set)
      let result = intBytes;
      if (result.length > 1 && result[0] === 0x00) {
        result = result.slice(1);
      }

      // Check bounds (r and s must be <= 32 bytes for secp256k1)
      if (result.length > 32) return null;

      // Pad to 32 bytes
      if (result.length < 32) {
        const padded = new Uint8Array(32);
        padded.set(result, 32 - result.length);
        return padded;
      }

      return result;
    };

    // Parse r
    const rBytes = parseInteger();
    if (!rBytes) return null;

    // Parse s
    const sBytes = parseInteger();
    if (!sBytes) return null;

    // Verify we consumed all bytes
    if (pos !== der.length) return null;

    // Combine r and s
    const compact = new Uint8Array(64);
    compact.set(rBytes, 0);
    compact.set(sBytes, 32);

    return compact;
  } catch {
    return null;
  }
}

// Helper to check if S is high (greater than half the curve order)
function isHighS(signature: Uint8Array): boolean {
  // secp256k1 curve order n
  const CURVE_N_HALF = BigInt(
    '0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0',
  );

  // Extract s from signature (last 32 bytes)
  const sBytes = signature.slice(32, 64);
  let s = BigInt(0);
  for (const byte of sBytes) {
    s = (s << BigInt(8)) | BigInt(byte);
  }

  return s > CURVE_N_HALF;
}

// Cast vectors to proper types
const typedEcdsaVectors = ecdsaVectors as ECDSAVectors;
const typedWycheproofVectors = wycheproofVectors as WycheproofVectors;

/**
 * Test basic ECDSA verify functionality with valid signatures from ecdsa.json
 * These are RFC 6979 deterministic signatures
 */
export const testEcdsaVerifyValidVectors = (): TestResult[] => {
  let passed = 0;
  let failed = 0;
  const failures: string[] = [];

  for (const vector of typedEcdsaVectors.valid) {
    try {
      // Generate public key from private key
      const pubKey = getPublicKey(vector.d, false); // uncompressed
      const msgHash = hexToUint8Array(vector.m);
      const signature = hexToUint8Array(vector.signature);

      // Verify with prehash=false since message is already a hash
      const isValid = verify(signature, msgHash, pubKey, {
        prehash: false,
        lowS: true,
        format: 'compact',
      });

      if (isValid) {
        passed++;
      } else {
        failed++;
        if (failures.length < 3) {
          const desc =
            vector.description?.slice(0, 30) || `d=${vector.d.slice(0, 8)}`;
          failures.push(desc);
        }
      }
    } catch (error) {
      failed++;
      if (failures.length < 3) {
        const desc =
          vector.description?.slice(0, 30) || `d=${vector.d.slice(0, 8)}`;
        failures.push(
          `${desc}: ${error instanceof Error ? error.message : 'error'}`,
        );
      }
    }
  }

  const total = passed + failed;
  return [
    {
      name: `Valid signatures (${total} vectors)`,
      success: failed === 0,
      message:
        failed === 0
          ? `✓ All ${passed} valid signatures verified`
          : `✗ ${failed}/${total} failed. First failures: ${failures.join('; ')}`,
    },
  ];
};

/**
 * Test ECDSA verify with compressed public keys
 */
export const testEcdsaVerifyCompressedPubKey = (): TestResult[] => {
  let passed = 0;
  let failed = 0;
  const failures: string[] = [];

  // Use first few vectors for compressed key test
  const testVectors = typedEcdsaVectors.valid.slice(0, 10);

  for (const vector of testVectors) {
    try {
      // Generate compressed public key
      const pubKey = getPublicKey(vector.d, true); // compressed
      const msgHash = hexToUint8Array(vector.m);
      const signature = hexToUint8Array(vector.signature);

      const isValid = verify(signature, msgHash, pubKey, {
        prehash: false,
        lowS: true,
        format: 'compact',
      });

      if (isValid) {
        passed++;
      } else {
        failed++;
        if (failures.length < 3) {
          failures.push(
            vector.description?.slice(0, 20) || `d=${vector.d.slice(0, 8)}`,
          );
        }
      }
    } catch (error) {
      failed++;
      if (failures.length < 3) {
        failures.push(`${error instanceof Error ? error.message : 'error'}`);
      }
    }
  }

  const total = passed + failed;
  return [
    {
      name: `Compressed pubkey verification (${total} vectors)`,
      success: failed === 0,
      message:
        failed === 0
          ? `✓ All ${passed} signatures verified with compressed keys`
          : `✗ ${failed}/${total} failed: ${failures.join('; ')}`,
    },
  ];
};

/**
 * Test ECDSA verify rejects ALL invalid vectors from ecdsa.json
 * This includes bad public key formats, invalid coordinates, and invalid r/s values
 */
export const testEcdsaVerifyInvalidVectors = (): TestResult[] => {
  let passed = 0;
  let failed = 0;
  const failures: string[] = [];

  for (const vector of typedEcdsaVectors.invalid.verify) {
    try {
      const pubKey = hexToUint8Array(vector.Q);
      const msgHash = hexToUint8Array(vector.m);
      const signature = hexToUint8Array(vector.signature);

      // For strict tests with high S, use lowS=true
      const lowS = vector.strict === true;

      const isValid = verify(signature, msgHash, pubKey, {
        prehash: false,
        lowS: lowS,
        format: 'compact',
      });

      if (!isValid) {
        passed++; // Correctly rejected
      } else {
        failed++;
        if (failures.length < 3) {
          failures.push(vector.description);
        }
      }
    } catch (error) {
      // Throwing is also acceptable for invalid inputs
      passed++;
    }
  }

  const total = passed + failed;
  return [
    {
      name: `Invalid signature rejection (${total} vectors)`,
      success: failed === 0,
      message:
        failed === 0
          ? `✓ All ${passed} invalid inputs correctly rejected`
          : `✗ ${failed}/${total} were incorrectly accepted: ${failures.join('; ')}`,
    },
  ];
};

// secp256k1 curve order n
const CURVE_N = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);

// Helper to convert a low-S signature to high-S by computing s' = n - s
function toHighS(signature: Uint8Array): Uint8Array {
  // Extract s from signature (last 32 bytes)
  const sBytes = signature.slice(32, 64);
  let s = BigInt(0);
  for (const byte of sBytes) {
    s = (s << BigInt(8)) | BigInt(byte);
  }

  // Compute high-S: s' = n - s
  const highS = CURVE_N - s;

  // Convert back to bytes
  const newSig = new Uint8Array(64);
  newSig.set(signature.slice(0, 32), 0); // Keep r

  let temp = highS;
  for (let i = 31; i >= 0; i--) {
    newSig[32 + i] = Number(temp & BigInt(0xff));
    temp = temp >> BigInt(8);
  }

  return newSig;
}

/**
 * Test lowS option - signatures with high S should be rejected when lowS=true
 */
export const testEcdsaVerifyLowS = (): TestResult[] => {
  const results: TestResult[] = [];

  // Use a valid low-S signature and convert it to high-S
  const vector = typedEcdsaVectors.valid[0]!;
  const pubKey = getPublicKey(vector.d, false);
  const msgHash = hexToUint8Array(vector.m);
  const lowSSignature = hexToUint8Array(vector.signature);
  const highSSignature = toHighS(lowSSignature);

  try {
    // Test low-S signature with lowS=true (should accept)
    const lowSAcceptedWithLowSOption = verify(lowSSignature, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'compact',
    });

    results.push({
      name: 'Low-S signature accepted with lowS=true',
      success: lowSAcceptedWithLowSOption,
      message: lowSAcceptedWithLowSOption
        ? '✓ Low-S signature accepted with lowS=true'
        : '✗ Low-S signature rejected with lowS=true',
    });

    // Test low-S signature with lowS=false (should also accept)
    const lowSAcceptedWithoutLowSOption = verify(
      lowSSignature,
      msgHash,
      pubKey,
      {
        prehash: false,
        lowS: false,
        format: 'compact',
      },
    );

    results.push({
      name: 'Low-S signature accepted with lowS=false',
      success: lowSAcceptedWithoutLowSOption,
      message: lowSAcceptedWithoutLowSOption
        ? '✓ Low-S signature accepted with lowS=false'
        : '✗ Low-S signature rejected with lowS=false',
    });

    // Test high-S signature with lowS=true (should REJECT)
    // This is the critical test - Bitcoin/Ethereum reject high-S for malleability protection
    const highSRejectedWithLowSOption = verify(
      highSSignature,
      msgHash,
      pubKey,
      {
        prehash: false,
        lowS: true,
        format: 'compact',
      },
    );

    results.push({
      name: 'High-S signature rejected with lowS=true',
      success: !highSRejectedWithLowSOption,
      message: !highSRejectedWithLowSOption
        ? '✓ High-S signature correctly rejected with lowS=true'
        : '✗ High-S signature should be rejected with lowS=true',
    });

    // Test high-S signature with lowS=false (should ACCEPT)
    // Both (r, s) and (r, n-s) are mathematically valid signatures
    // This matches noble-curves behavior: verify(highS_sig, ..., {lowS: false}) === true
    const highSAcceptedWithoutLowSOption = verify(
      highSSignature,
      msgHash,
      pubKey,
      {
        prehash: false,
        lowS: false,
        format: 'compact',
      },
    );

    results.push({
      name: 'High-S signature accepted with lowS=false',
      success: highSAcceptedWithoutLowSOption,
      message: highSAcceptedWithoutLowSOption
        ? '✓ High-S signature correctly accepted with lowS=false'
        : '✗ High-S signature should be accepted with lowS=false',
    });
  } catch (error) {
    results.push({
      name: 'lowS option test',
      success: false,
      message: `Error: ${error instanceof Error ? error.message : String(error)}`,
    });
  }

  return results;
};

/**
 * Test prehash option - verify that SHA-256 hashing works correctly
 */
export const testEcdsaVerifyPrehash = (): TestResult[] => {
  const results: TestResult[] = [];

  const vector = typedEcdsaVectors.valid[0]!;
  const pubKey = getPublicKey(vector.d, false);
  const msgHash = hexToUint8Array(vector.m);
  const signature = hexToUint8Array(vector.signature);

  try {
    // Test prehash=false with 32-byte hash (should work)
    const validPrehashFalse = verify(signature, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'compact',
    });

    results.push({
      name: 'prehash=false with 32-byte hash',
      success: validPrehashFalse,
      message: validPrehashFalse
        ? '✓ Verification works with prehash=false and 32-byte hash'
        : '✗ Verification failed with prehash=false and 32-byte hash',
    });

    // Test prehash=false with non-32-byte data (should fail)
    const shortMessage = new Uint8Array([1, 2, 3, 4]);
    const invalidPrehashFalse = verify(signature, shortMessage, pubKey, {
      prehash: false,
      lowS: true,
      format: 'compact',
    });

    results.push({
      name: 'prehash=false with short message rejects',
      success: !invalidPrehashFalse,
      message: !invalidPrehashFalse
        ? '✓ Correctly rejected non-32-byte message with prehash=false'
        : '✗ Should reject non-32-byte message with prehash=false',
    });
  } catch (error) {
    results.push({
      name: 'prehash option test',
      success: false,
      message: `Error: ${error instanceof Error ? error.message : String(error)}`,
    });
  }

  return results;
};

/**
 * Test wrong signature for valid public key/message
 */
export const testEcdsaVerifyWrongSignature = (): TestResult[] => {
  const results: TestResult[] = [];

  const vector = typedEcdsaVectors.valid[0]!;
  const pubKey = getPublicKey(vector.d, false);
  const msgHash = hexToUint8Array(vector.m);

  // Use signature from a different vector
  const wrongSignature = hexToUint8Array(typedEcdsaVectors.valid[1]!.signature);

  try {
    const isValid = verify(wrongSignature, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'compact',
    });

    results.push({
      name: 'Rejects wrong signature',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected wrong signature'
        : '✗ Should have rejected wrong signature',
    });
  } catch (error) {
    results.push({
      name: 'Rejects wrong signature',
      success: true,
      message: '✓ Threw error for wrong signature',
    });
  }

  return results;
};

/**
 * Test wrong message for valid signature/public key
 */
export const testEcdsaVerifyWrongMessage = (): TestResult[] => {
  const results: TestResult[] = [];

  const vector = typedEcdsaVectors.valid[0]!;
  const pubKey = getPublicKey(vector.d, false);
  const signature = hexToUint8Array(vector.signature);

  // Use message hash from a different vector
  const wrongMsgHash = hexToUint8Array(typedEcdsaVectors.valid[1]!.m);

  try {
    const isValid = verify(signature, wrongMsgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'compact',
    });

    results.push({
      name: 'Rejects wrong message',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected wrong message'
        : '✗ Should have rejected wrong message',
    });
  } catch (error) {
    results.push({
      name: 'Rejects wrong message',
      success: true,
      message: '✓ Threw error for wrong message',
    });
  }

  return results;
};

/**
 * Test type validation for verify function
 */
export const testEcdsaVerifyTypeValidation = (): TestResult[] => {
  const results: TestResult[] = [];

  const vector = typedEcdsaVectors.valid[0]!;
  const pubKey = getPublicKey(vector.d, false);
  const msgHash = hexToUint8Array(vector.m);
  const signature = hexToUint8Array(vector.signature);

  // Test invalid signature type
  try {
    verify('invalid' as any, msgHash, pubKey, { prehash: false });
    results.push({
      name: 'Rejects string signature',
      success: false,
      message: '✗ Should have rejected string signature',
    });
  } catch (error) {
    results.push({
      name: 'Rejects string signature',
      success: true,
      message: '✓ Correctly rejected string signature',
    });
  }

  // Test invalid message type
  try {
    verify(signature, 'invalid' as any, pubKey, { prehash: false });
    results.push({
      name: 'Rejects string message',
      success: false,
      message: '✗ Should have rejected string message',
    });
  } catch (error) {
    results.push({
      name: 'Rejects string message',
      success: true,
      message: '✓ Correctly rejected string message',
    });
  }

  // Test invalid pubKey type
  try {
    verify(signature, msgHash, 'invalid' as any, { prehash: false });
    results.push({
      name: 'Rejects string public key',
      success: false,
      message: '✗ Should have rejected string public key',
    });
  } catch (error) {
    results.push({
      name: 'Rejects string public key',
      success: true,
      message: '✓ Correctly rejected string public key',
    });
  }

  return results;
};

/**
 * Test edge cases: invalid r and s values
 */
export const testEcdsaVerifyEdgeCases = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test r=0, s=0
  const zeroSig = new Uint8Array(64).fill(0);
  const validPubKey = hexToUint8Array(
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  );
  const msgHash = hexToUint8Array(
    '0000000000000000000000000000000000000000000000000000000000000003',
  );

  try {
    const isValid = verify(zeroSig, msgHash, validPubKey, {
      prehash: false,
      lowS: false,
      format: 'compact',
    });
    results.push({
      name: 'Rejects r=0, s=0 signature',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected r=0, s=0 signature'
        : '✗ Should reject r=0, s=0 signature',
    });
  } catch {
    results.push({
      name: 'Rejects r=0, s=0 signature',
      success: true,
      message: '✓ Threw error for r=0, s=0 signature',
    });
  }

  // Test r=0, s=1
  const rZeroSig = new Uint8Array(64);
  rZeroSig[63] = 1; // s = 1
  try {
    const isValid = verify(rZeroSig, msgHash, validPubKey, {
      prehash: false,
      lowS: false,
      format: 'compact',
    });
    results.push({
      name: 'Rejects r=0 signature',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected r=0 signature'
        : '✗ Should reject r=0 signature',
    });
  } catch {
    results.push({
      name: 'Rejects r=0 signature',
      success: true,
      message: '✓ Threw error for r=0 signature',
    });
  }

  // Test r=1, s=0
  const sZeroSig = new Uint8Array(64);
  sZeroSig[31] = 1; // r = 1
  try {
    const isValid = verify(sZeroSig, msgHash, validPubKey, {
      prehash: false,
      lowS: false,
      format: 'compact',
    });
    results.push({
      name: 'Rejects s=0 signature',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected s=0 signature'
        : '✗ Should reject s=0 signature',
    });
  } catch {
    results.push({
      name: 'Rejects s=0 signature',
      success: true,
      message: '✓ Threw error for s=0 signature',
    });
  }

  // Test r >= n (curve order)
  // n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  const rOverflowSig = hexToUint8Array(
    'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141' +
      '0000000000000000000000000000000000000000000000000000000000000001',
  );
  try {
    const isValid = verify(rOverflowSig, msgHash, validPubKey, {
      prehash: false,
      lowS: false,
      format: 'compact',
    });
    results.push({
      name: 'Rejects r >= n signature',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected r >= n signature'
        : '✗ Should reject r >= n signature',
    });
  } catch {
    results.push({
      name: 'Rejects r >= n signature',
      success: true,
      message: '✓ Threw error for r >= n signature',
    });
  }

  // Test s >= n
  const sOverflowSig = hexToUint8Array(
    '0000000000000000000000000000000000000000000000000000000000000001' +
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  );
  try {
    const isValid = verify(sOverflowSig, msgHash, validPubKey, {
      prehash: false,
      lowS: false,
      format: 'compact',
    });
    results.push({
      name: 'Rejects s >= n signature',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected s >= n signature'
        : '✗ Should reject s >= n signature',
    });
  } catch {
    results.push({
      name: 'Rejects s >= n signature',
      success: true,
      message: '✓ Threw error for s >= n signature',
    });
  }

  // Test message hash = n (curve order) - should fail verification
  const curveOrderMsg = hexToUint8Array(
    'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  );
  const vector = typedEcdsaVectors.valid[0]!;
  const pubKey = getPublicKey(vector.d, false);
  const validSig = hexToUint8Array(vector.signature);
  try {
    const isValid = verify(validSig, curveOrderMsg, pubKey, {
      prehash: false,
      lowS: true,
      format: 'compact',
    });
    results.push({
      name: 'Message hash = curve order fails verification',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly failed verification with msg = n'
        : '✗ Verification should fail with msg = n',
    });
  } catch {
    results.push({
      name: 'Message hash = curve order fails verification',
      success: true,
      message: '✓ Threw error for msg = curve order',
    });
  }

  return results;
};

/**
 * Test Wycheproof vectors - comprehensive security test suite
 * Uses DER format signatures with SHA-256 prehashing
 *
 * This test matches noble-curves' behavior:
 * - Default lowS=true (reject high-S signatures for malleability protection)
 * - Valid signatures with high-S are expected to FAIL (standard Bitcoin/Ethereum behavior)
 * - Valid signatures with low-S are expected to PASS
 * - Invalid signatures are expected to FAIL
 */
export const testEcdsaVerifyWycheproof = (): TestResult[] => {
  let passedCount = 0;
  let failedCount = 0;
  const failures: string[] = [];

  for (const group of typedWycheproofVectors.testGroups) {
    const pubKeyHex = group.publicKey.uncompressed;
    const pubKey = hexToUint8Array(pubKeyHex);

    for (const test of group.tests) {
      try {
        const msg = hexToUint8Array(test.msg);

        // Parse DER signature to compact format using strict DER validation
        const compactSig = parseDERSignature(test.sig);

        if (!compactSig) {
          // Invalid DER encoding - should be rejected
          if (test.result === 'invalid') {
            passedCount++;
            continue;
          }
          // Valid signature with invalid DER - this is a parser issue
          failedCount++;
          if (failures.length < 3) {
            failures.push(`tcId=${test.tcId}: DER parse failed`);
          }
          continue;
        }

        // Check if signature has high S
        const hasHighS = isHighS(compactSig);

        // Verify with default lowS=true (standard noble-curves/Bitcoin/Ethereum behavior)
        // This rejects high-S signatures for malleability protection
        const isValid = verify(compactSig, msg, pubKey, {
          prehash: true, // SHA-256 hash the message
          lowS: true, // Enforce low-S (default, matches noble-curves)
          format: 'compact',
        });

        const expectedValid =
          test.result === 'valid' || test.result === 'acceptable';

        // Determine expected result based on noble-curves behavior:
        // - Valid signatures with high-S should FAIL (lowS enforcement)
        // - Valid signatures with low-S should PASS
        // - Invalid signatures should FAIL
        let expectedResult: boolean;
        if (expectedValid && hasHighS) {
          // High-S valid signatures are rejected by lowS enforcement
          expectedResult = false;
        } else if (expectedValid) {
          // Low-S valid signatures should pass
          expectedResult = true;
        } else {
          // Invalid signatures should fail
          expectedResult = false;
        }

        if (isValid === expectedResult) {
          passedCount++;
        } else {
          failedCount++;
          if (failures.length < 3) {
            const expected = expectedResult ? 'valid' : 'invalid';
            const got = isValid ? 'valid' : 'invalid';
            failures.push(
              `tcId=${test.tcId}: expected ${expected}, got ${got}`,
            );
          }
        }
      } catch (error) {
        // Errors for invalid vectors are acceptable
        if (test.result === 'invalid') {
          passedCount++;
        } else {
          failedCount++;
          if (failures.length < 3) {
            failures.push(
              `tcId=${test.tcId}: ${error instanceof Error ? error.message : 'error'}`,
            );
          }
        }
      }
    }
  }

  const total = typedWycheproofVectors.numberOfTests;
  return [
    {
      name: `Wycheproof vectors (${total} tests)`,
      success: failedCount === 0,
      message:
        failedCount === 0
          ? `✓ All ${passedCount} Wycheproof tests passed`
          : `✗ ${failedCount}/${passedCount + failedCount} failed: ${failures.join('; ')}`,
    },
  ];
};

/**
 * Test DER format signature verification
 */
export const testEcdsaVerifyDERFormat = (): TestResult[] => {
  const results: TestResult[] = [];

  // Use first Wycheproof test group which has known DER signatures
  const group = typedWycheproofVectors.testGroups[0];
  if (!group) {
    results.push({
      name: 'DER format test',
      success: false,
      message: 'No test group found',
    });
    return results;
  }

  const pubKey = hexToUint8Array(group.publicKey.uncompressed);

  // Find a valid low-S DER signature (high-S would be rejected with default lowS=true)
  const validTest = group.tests.find((t) => {
    if (t.result !== 'valid') return false;
    // Parse and check if low-S
    const compact = parseDERSignature(t.sig);
    return compact && !isHighS(compact);
  });

  if (validTest) {
    try {
      const msg = hexToUint8Array(validTest.msg);
      const derSig = hexToUint8Array(validTest.sig);

      const isValid = verify(derSig, msg, pubKey, {
        prehash: true,
        lowS: true, // Use default lowS=true
        format: 'der',
      });

      results.push({
        name: 'Valid DER signature verification',
        success: isValid,
        message: isValid
          ? '✓ DER signature verified successfully'
          : '✗ Valid DER signature was rejected',
      });
    } catch (error) {
      results.push({
        name: 'Valid DER signature verification',
        success: false,
        message: `Error: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  } else {
    results.push({
      name: 'Valid DER signature verification',
      success: false,
      message: '✗ No valid low-S signature found in test vectors',
    });
  }

  // Test invalid DER signature
  const invalidTest = group.tests.find((t) => t.result === 'invalid');
  if (invalidTest) {
    try {
      const msg = hexToUint8Array(invalidTest.msg);
      const derSig = hexToUint8Array(invalidTest.sig);

      const isValid = verify(derSig, msg, pubKey, {
        prehash: true,
        lowS: false,
        format: 'der',
      });

      results.push({
        name: 'Invalid DER signature rejection',
        success: !isValid,
        message: !isValid
          ? '✓ Invalid DER signature correctly rejected'
          : '✗ Invalid DER signature should be rejected',
      });
    } catch (error) {
      // Throwing is also acceptable for invalid DER
      results.push({
        name: 'Invalid DER signature rejection',
        success: true,
        message: '✓ Threw error for invalid DER signature',
      });
    }
  }

  return results;
};

/**
 * Test recovered format (65 bytes: recovery byte + compact signature)
 */
export const testEcdsaVerifyRecoveredFormat = (): TestResult[] => {
  const results: TestResult[] = [];

  const vector = typedEcdsaVectors.valid[0]!;
  const pubKey = getPublicKey(vector.d, false);
  const msgHash = hexToUint8Array(vector.m);
  const compactSig = hexToUint8Array(vector.signature);

  // Create recovered format (prepend recovery byte 0)
  const recoveredSig = new Uint8Array(65);
  recoveredSig[0] = 0; // Recovery byte
  recoveredSig.set(compactSig, 1);

  try {
    const isValid = verify(recoveredSig, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'recovered',
    });

    results.push({
      name: 'Recovered format signature verification',
      success: isValid,
      message: isValid
        ? '✓ Recovered format signature verified'
        : '✗ Recovered format signature verification failed',
    });
  } catch (error) {
    results.push({
      name: 'Recovered format signature verification',
      success: false,
      message: `Error: ${error instanceof Error ? error.message : String(error)}`,
    });
  }

  // Test with recovery byte 1
  recoveredSig[0] = 1;
  try {
    const isValid = verify(recoveredSig, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'recovered',
    });

    results.push({
      name: 'Recovered format with recovery=1',
      success: isValid,
      message: isValid
        ? '✓ Recovered format (recovery=1) verified'
        : '✗ Recovered format (recovery=1) failed',
    });
  } catch (error) {
    results.push({
      name: 'Recovered format with recovery=1',
      success: false,
      message: `Error: ${error instanceof Error ? error.message : String(error)}`,
    });
  }

  // Test wrong length for recovered format
  const wrongLengthSig = new Uint8Array(64); // Should be 65
  try {
    const isValid = verify(wrongLengthSig, msgHash, pubKey, {
      prehash: false,
      lowS: false,
      format: 'recovered',
    });

    results.push({
      name: 'Rejects wrong length for recovered format',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected 64-byte signature for recovered format'
        : '✗ Should reject wrong length signature',
    });
  } catch {
    results.push({
      name: 'Rejects wrong length for recovered format',
      success: true,
      message: '✓ Threw error for wrong length recovered signature',
    });
  }

  return results;
};

/**
 * Direct comparison test with noble/curves secp256k1.verify
 * This ensures our native implementation produces identical results to noble/curves
 * for the same inputs across all test vectors.
 */
export const testDirectNobleComparison = (): TestResult[] => {
  let passed = 0;
  let failed = 0;
  const failures: string[] = [];

  // Test all valid vectors with direct comparison
  for (const vector of typedEcdsaVectors.valid) {
    try {
      const msgHash = hexToUint8Array(vector.m);
      const signature = hexToUint8Array(vector.signature);

      // Generate public keys using both implementations
      const nativePubKey = getPublicKey(vector.d, false);
      const noblePubKey = secp256k1.getPublicKey(
        hexToUint8Array(vector.d),
        false,
      );

      // Verify with native implementation
      const nativeResult = verify(signature, msgHash, nativePubKey, {
        prehash: false,
        lowS: true,
        format: 'compact',
      });

      // Verify with noble/curves
      const nobleResult = secp256k1.verify(signature, msgHash, noblePubKey, {
        prehash: false,
        lowS: true,
      });

      if (nativeResult === nobleResult) {
        passed++;
      } else {
        failed++;
        if (failures.length < 3) {
          const desc =
            vector.description?.slice(0, 25) || `d=${vector.d.slice(0, 8)}`;
          failures.push(
            `${desc}: native=${nativeResult}, noble=${nobleResult}`,
          );
        }
      }
    } catch (error) {
      failed++;
      if (failures.length < 3) {
        const desc =
          vector.description?.slice(0, 25) || `d=${vector.d.slice(0, 8)}`;
        failures.push(
          `${desc}: ${error instanceof Error ? error.message : 'error'}`,
        );
      }
    }
  }

  // Test lowS=false behavior comparison
  const lowSFalseTests: { passed: number; failed: number } = {
    passed: 0,
    failed: 0,
  };
  for (let i = 0; i < Math.min(10, typedEcdsaVectors.valid.length); i++) {
    const vector = typedEcdsaVectors.valid[i]!;
    try {
      const msgHash = hexToUint8Array(vector.m);
      const signature = hexToUint8Array(vector.signature);
      const nativePubKey = getPublicKey(vector.d, false);

      // Create high-S signature
      const highSSig = toHighS(signature);

      const nativeHighSResult = verify(highSSig, msgHash, nativePubKey, {
        prehash: false,
        lowS: false,
        format: 'compact',
      });

      const nobleHighSResult = secp256k1.verify(
        highSSig,
        msgHash,
        nativePubKey,
        {
          prehash: false,
          lowS: false,
        },
      );

      if (nativeHighSResult === nobleHighSResult) {
        lowSFalseTests.passed++;
      } else {
        lowSFalseTests.failed++;
      }
    } catch {
      lowSFalseTests.failed++;
    }
  }

  const total = passed + failed;
  return [
    {
      name: `Direct noble/curves comparison (${total} vectors)`,
      success: failed === 0,
      message:
        failed === 0
          ? `✓ All ${passed} results match noble/curves exactly`
          : `✗ ${failed}/${total} mismatches: ${failures.join('; ')}`,
    },
    {
      name: `lowS=false behavior comparison (${lowSFalseTests.passed + lowSFalseTests.failed} tests)`,
      success: lowSFalseTests.failed === 0,
      message:
        lowSFalseTests.failed === 0
          ? `✓ High-S signature handling matches noble/curves`
          : `✗ ${lowSFalseTests.failed} mismatches in high-S handling`,
    },
  ];
};

/**
 * Test prehash=true with real messages (not pre-hashed)
 * Signs a message with noble/curves and verifies with native implementation
 */
export const testPrehashWithRealMessage = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test 1: Sign with noble, verify with native
  try {
    const privateKeyHex =
      '0000000000000000000000000000000000000000000000000000000000000001';
    const privateKey = hexToUint8Array(privateKeyHex);
    const message = new TextEncoder().encode('hello world');

    // Sign with noble (uses SHA-256 by default)
    const nobleSig = secp256k1.sign(message, privateKey, { prehash: true }); // prehash defaults to false in noble-curves
    const noblePubKey = secp256k1.getPublicKey(privateKey);

    // Verify noble signature with noble (sanity check)
    const nobleVerifies = secp256k1.verify(
      nobleSig.toCompactRawBytes(),
      message,
      noblePubKey,
      { prehash: true, lowS: true, format: 'compact' },
    );

    // Verify noble signature with native
    const nativeVerifies = verify(
      nobleSig.toCompactRawBytes(),
      message,
      noblePubKey,
      {
        prehash: true,
        lowS: true,
        format: 'compact',
      },
    );

    results.push({
      name: 'Noble signature verified by native (prehash=true)',
      success: nativeVerifies && nobleVerifies,
      message:
        nativeVerifies && nobleVerifies
          ? '✓ Native verified noble signature with prehash=true'
          : `✗ Noble verified: ${nobleVerifies}, Native verified: ${nativeVerifies}`,
    });
  } catch (error) {
    results.push({
      name: 'Noble signature verified by native (prehash=true)',
      success: false,
      message: `Error: ${error instanceof Error ? error.message : String(error)}`,
    });
  }

  // Test 2: Various message lengths with prehash=true
  const testMessages = [
    '', // empty string
    'a',
    'hello',
    'The quick brown fox jumps over the lazy dog',
    'x'.repeat(1000), // longer message
  ];

  for (const msg of testMessages) {
    try {
      const privateKey = hexToUint8Array(
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
      );
      const message = new TextEncoder().encode(msg);

      const nobleSig = secp256k1.sign(message, privateKey, { prehash: true });
      const noblePubKey = secp256k1.getPublicKey(privateKey);

      const nobleVerifies = secp256k1.verify(
        nobleSig.toCompactRawBytes(),
        message,
        noblePubKey,
        { prehash: true, lowS: true, format: 'compact' },
      );
      const nativeVerifies = verify(
        nobleSig.toCompactRawBytes(),
        message,
        noblePubKey,
        {
          prehash: true,
          lowS: true,
          format: 'compact',
        },
      );

      if (nobleVerifies !== nativeVerifies) {
        results.push({
          name: `Prehash message length ${msg.length}`,
          success: false,
          message: `✗ Mismatch: noble=${nobleVerifies}, native=${nativeVerifies}`,
        });
      }
    } catch (error) {
      results.push({
        name: `Prehash message length ${msg.length}`,
        success: false,
        message: `Error: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  // If all message tests passed, add a summary
  if (results.length === 1) {
    results.push({
      name: `Prehash various message lengths (${testMessages.length} tests)`,
      success: true,
      message: '✓ All message lengths verified correctly with prehash=true',
    });
  }

  // Test 3: Verify that prehash=false fails with wrong hash
  try {
    const privateKey = hexToUint8Array(
      '0000000000000000000000000000000000000000000000000000000000000001',
    );
    const message = new TextEncoder().encode('test message');

    const nobleSig = secp256k1.sign(message, privateKey, { prehash: true }); // SHA-256 prehash
    const noblePubKey = secp256k1.getPublicKey(privateKey);

    // Try to verify with raw message (not hashed) and prehash=false - should fail
    // because the message isn't 32 bytes
    const shouldFail = verify(
      nobleSig.toCompactRawBytes(),
      message,
      noblePubKey,
      {
        prehash: false,
        lowS: true,
        format: 'compact',
      },
    );

    results.push({
      name: 'prehash=false rejects non-32-byte message',
      success: !shouldFail,
      message: !shouldFail
        ? '✓ Correctly rejected non-32-byte message with prehash=false'
        : '✗ Should have rejected non-32-byte message',
    });
  } catch {
    results.push({
      name: 'prehash=false rejects non-32-byte message',
      success: true,
      message: '✓ Threw error for non-32-byte message with prehash=false',
    });
  }

  return results;
};

/**
 * Fuzz test for DER parsing edge cases
 * Tests various malformed DER signatures to ensure robust rejection
 */
export const testDerParsingFuzz = (): TestResult[] => {
  const results: TestResult[] = [];

  // Test data from a valid signature
  const vector = typedEcdsaVectors.valid[0]!;
  const pubKey = getPublicKey(vector.d, false);
  const msgHash = hexToUint8Array(vector.m);

  // Test 1: BER long-form length encoding (should be rejected)
  // 0x30 0x81 0x44 means SEQUENCE with long-form length (0x81 = 1 byte follows for length)
  // This is valid BER but should be rejected as non-canonical DER
  const berLongForm = hexToUint8Array(
    '308144' + // SEQUENCE with BER long-form length (0x81 0x44 = 68 bytes)
      '0220' +
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
      '0220' +
      '0c9e8b6e6c0c4d4df9d3c3b8e8c7c7b8b6e6c0c4d4df9d3c3b8e8c7c7b8b6e6c',
  );
  try {
    const isValid = verify(berLongForm, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'der',
    });
    results.push({
      name: 'BER long-form length encoding rejected',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected BER long-form encoding'
        : '✗ Should reject BER long-form length encoding',
    });
  } catch {
    results.push({
      name: 'BER long-form length encoding rejected',
      success: true,
      message: '✓ Threw error for BER long-form encoding',
    });
  }

  // Test 2: Wrong tag (not SEQUENCE)
  // Using 0x31 (SET) instead of 0x30 (SEQUENCE)
  const wrongTag = hexToUint8Array(
    '3144' + // SET tag instead of SEQUENCE
      '0220' +
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
      '0220' +
      '0c9e8b6e6c0c4d4df9d3c3b8e8c7c7b8b6e6c0c4d4df9d3c3b8e8c7c7b8b6e6c',
  );
  try {
    const isValid = verify(wrongTag, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'der',
    });
    results.push({
      name: 'Wrong SEQUENCE tag rejected',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected wrong SEQUENCE tag'
        : '✗ Should reject wrong SEQUENCE tag',
    });
  } catch {
    results.push({
      name: 'Wrong SEQUENCE tag rejected',
      success: true,
      message: '✓ Threw error for wrong SEQUENCE tag',
    });
  }

  // Test 3: Incorrect sequence length (too short)
  const wrongSeqLength = hexToUint8Array(
    '3043' + // Wrong length (0x43 instead of 0x44)
      '0220' +
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
      '0220' +
      '0c9e8b6e6c0c4d4df9d3c3b8e8c7c7b8b6e6c0c4d4df9d3c3b8e8c7c7b8b6e6c',
  );
  try {
    const isValid = verify(wrongSeqLength, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'der',
    });
    results.push({
      name: 'Incorrect sequence length rejected',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected incorrect sequence length'
        : '✗ Should reject incorrect sequence length',
    });
  } catch {
    results.push({
      name: 'Incorrect sequence length rejected',
      success: true,
      message: '✓ Threw error for incorrect sequence length',
    });
  }

  // Test 4: Truncated signature (too short)
  const truncated = hexToUint8Array('3044022079be667ef9dcbbac55a0');
  try {
    const isValid = verify(truncated, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'der',
    });
    results.push({
      name: 'Truncated DER signature rejected',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected truncated signature'
        : '✗ Should reject truncated signature',
    });
  } catch {
    results.push({
      name: 'Truncated DER signature rejected',
      success: true,
      message: '✓ Threw error for truncated signature',
    });
  }

  // Test 5: Signature too long (> 73 bytes)
  const tooLong = hexToUint8Array(
    '3050' + // Oversized length
      '0228' +
      '0000000079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
      '0224' +
      '000000000c9e8b6e6c0c4d4df9d3c3b8e8c7c7b8b6e6c0c4d4df9d3c3b8e8c7c7b80',
  );
  try {
    const isValid = verify(tooLong, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'der',
    });
    results.push({
      name: 'Oversized DER signature rejected',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected oversized signature'
        : '✗ Should reject oversized signature',
    });
  } catch {
    results.push({
      name: 'Oversized DER signature rejected',
      success: true,
      message: '✓ Threw error for oversized signature',
    });
  }

  // Test 6: Signature too short (< 8 bytes)
  const veryShort = hexToUint8Array('30020101'); // Only 4 bytes
  try {
    const isValid = verify(veryShort, msgHash, pubKey, {
      prehash: false,
      lowS: true,
      format: 'der',
    });
    results.push({
      name: 'Too short DER signature rejected',
      success: !isValid,
      message: !isValid
        ? '✓ Correctly rejected too short signature'
        : '✗ Should reject too short signature',
    });
  } catch {
    results.push({
      name: 'Too short DER signature rejected',
      success: true,
      message: '✓ Threw error for too short signature',
    });
  }

  return results;
};

/**
 * Test Wycheproof vectors using native DER format parsing
 * This tests the native DER parser directly rather than converting to compact first.
 */
export const testWycheproofDERNative = (): TestResult[] => {
  let passedCount = 0;
  let failedCount = 0;
  const failures: string[] = [];

  for (const group of typedWycheproofVectors.testGroups) {
    const pubKeyHex = group.publicKey.uncompressed;
    const pubKey = hexToUint8Array(pubKeyHex);

    for (const test of group.tests) {
      try {
        const msg = hexToUint8Array(test.msg);
        const derSig = hexToUint8Array(test.sig);

        // Test native DER parsing directly
        const nativeValid = verify(derSig, msg, pubKey, {
          prehash: true,
          lowS: true,
          format: 'der',
        });

        // Check if signature parsing would fail (invalid DER) or has high-S
        let isValidDER = false;
        let hasHighS = false;
        try {
          const nobleParsed = secp256k1.Signature.fromDER(derSig);
          isValidDER = true;
          hasHighS = nobleParsed.hasHighS();
        } catch {
          // Invalid DER
        }

        // Also verify with noble for comparison (only for valid low-S DER)
        let nobleResult = false;
        if (isValidDER && !hasHighS) {
          try {
            const nobleSig = secp256k1.Signature.fromDER(derSig);
            const msgHash = sha256(msg);
            nobleResult = secp256k1.verify(
              nobleSig.toCompactRawBytes(),
              msgHash,
              pubKey,
              {
                prehash: false,
                lowS: true,
              },
            );
          } catch {
            nobleResult = false;
          }
        }

        // If DER is invalid or has high-S, both should reject
        if (!isValidDER || hasHighS) {
          if (!nativeValid) {
            passedCount++;
          } else {
            failedCount++;
            if (failures.length < 3) {
              failures.push(
                `tcId=${test.tcId}: native accepted invalid/highS DER`,
              );
            }
          }
        } else {
          // Valid low-S DER signature - compare with noble result
          if (nativeValid === nobleResult) {
            passedCount++;
          } else {
            failedCount++;
            if (failures.length < 3) {
              failures.push(
                `tcId=${test.tcId}: native=${nativeValid}, noble=${nobleResult}`,
              );
            }
          }
        }
      } catch (error) {
        // Throwing for invalid vectors is acceptable
        if (test.result === 'invalid') {
          passedCount++;
        } else {
          // Check if it's a high-S signature that should be rejected
          try {
            const derSig = hexToUint8Array(test.sig);
            const nobleSig = secp256k1.Signature.fromDER(derSig);
            if (nobleSig.hasHighS()) {
              passedCount++; // Correctly rejected high-S
            } else {
              failedCount++;
              if (failures.length < 3) {
                failures.push(
                  `tcId=${test.tcId}: threw error: ${error instanceof Error ? error.message : 'error'}`,
                );
              }
            }
          } catch {
            passedCount++; // Invalid DER, correctly rejected
          }
        }
      }
    }
  }

  const total = passedCount + failedCount;
  return [
    {
      name: `Wycheproof native DER parsing (${total} tests)`,
      success: failedCount === 0,
      message:
        failedCount === 0
          ? `✓ All ${passedCount} native DER tests passed`
          : `✗ ${failedCount}/${total} failed: ${failures.join('; ')}`,
    },
  ];
};

/**
 * Run all ECDSA verify tests
 */
export const runAllEcdsaVerifyTests = (): TestResult[] => {
  return [
    ...testEcdsaVerifyValidVectors(),
    ...testEcdsaVerifyCompressedPubKey(),
    ...testEcdsaVerifyInvalidVectors(),
    ...testEcdsaVerifyLowS(),
    ...testEcdsaVerifyPrehash(),
    ...testEcdsaVerifyWrongSignature(),
    ...testEcdsaVerifyWrongMessage(),
    ...testEcdsaVerifyTypeValidation(),
    ...testEcdsaVerifyEdgeCases(),
    ...testEcdsaVerifyDERFormat(),
    ...testEcdsaVerifyRecoveredFormat(),
    ...testEcdsaVerifyWycheproof(),
    ...testDirectNobleComparison(),
    ...testPrehashWithRealMessage(),
    ...testDerParsingFuzz(),
    ...testWycheproofDERNative(),
  ];
};
