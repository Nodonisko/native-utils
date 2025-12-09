import { verify } from '@metamask/native-utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

export interface BenchmarkResult {
  testName: string;
  native: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    operations: number;
    iops: number;
    standardDeviation: number;
  };
  javascript: {
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    operations: number;
    iops: number;
    standardDeviation: number;
  };
  comparison: {
    speedupFactor: number;
    nativeIsFaster: boolean;
    performanceGain: number;
  };
}

/**
 * Helper function to calculate standard deviation
 */
function calculateStandardDeviation(values: number[], mean: number): number {
  const squareDiffs = values.map((value) => Math.pow(value - mean, 2));
  const avgSquareDiff =
    squareDiffs.reduce((sum, value) => sum + value, 0) / values.length;
  return Math.sqrt(avgSquareDiff);
}

/**
 * Generate random private key for testing
 */
function generateRandomPrivateKey(): Uint8Array {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  // Ensure it's a valid private key (not zero, less than curve order)
  bytes[0] = bytes[0] || 1;
  return bytes;
}

interface TestData {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  message: Uint8Array;
  messageHash: Uint8Array;
  signature: Uint8Array;
}

/**
 * Generate test data with a valid signature
 */
function generateTestData(messageLength: number = 32): TestData {
  const privateKey = generateRandomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed
  const message = new Uint8Array(messageLength);
  for (let i = 0; i < messageLength; i++) {
    message[i] = Math.floor(Math.random() * 256);
  }
  const messageHash = sha256(message);

  // Sign with noble (using prehash=false, so we sign the hash directly)
  const sig = secp256k1.sign(messageHash, privateKey, { prehash: false });
  const signature = sig.toCompactRawBytes();

  return { privateKey, publicKey, message, messageHash, signature };
}

/**
 * Benchmark a specific scenario
 */
async function benchmarkScenario(
  testName: string,
  testData: TestData,
  iterations: number,
  usePrehash: boolean,
): Promise<BenchmarkResult> {
  const { publicKey, message, messageHash, signature } = testData;

  // Determine which message to use based on prehash setting
  const msgToVerify = usePrehash ? message : messageHash;

  // Warm up both implementations
  for (let i = 0; i < 10; i++) {
    verify(signature, msgToVerify, publicKey, {
      prehash: usePrehash,
      lowS: true,
      format: 'compact',
    });
    secp256k1.verify(signature, msgToVerify, publicKey, {
      prehash: usePrehash,
      lowS: true,
    });
  }

  // Benchmark native implementation
  const nativeTimes: number[] = [];
  const nativeStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    verify(signature, msgToVerify, publicKey, {
      prehash: usePrehash,
      lowS: true,
      format: 'compact',
    });
    const end = performance.now();
    nativeTimes.push(end - start);
  }

  const nativeEnd = performance.now();
  const nativeTotalTime = nativeEnd - nativeStart;

  // Small delay between runs
  await new Promise((resolve) => setTimeout(resolve, 10));

  // Benchmark JavaScript implementation (noble/curves)
  const jsTimes: number[] = [];
  const jsStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    secp256k1.verify(signature, msgToVerify, publicKey, {
      prehash: usePrehash,
      lowS: true,
    });
    const end = performance.now();
    jsTimes.push(end - start);
  }

  const jsEnd = performance.now();
  const jsTotalTime = jsEnd - jsStart;

  // Calculate statistics
  const nativeAvg = nativeTimes.reduce((a, b) => a + b, 0) / nativeTimes.length;
  const nativeMin = Math.min(...nativeTimes);
  const nativeMax = Math.max(...nativeTimes);
  const nativeStdDev = calculateStandardDeviation(nativeTimes, nativeAvg);
  const nativeIops = 1000 / nativeAvg;

  const jsAvg = jsTimes.reduce((a, b) => a + b, 0) / jsTimes.length;
  const jsMin = Math.min(...jsTimes);
  const jsMax = Math.max(...jsTimes);
  const jsStdDev = calculateStandardDeviation(jsTimes, jsAvg);
  const jsIops = 1000 / jsAvg;

  const speedupFactor = jsAvg / nativeAvg;
  const nativeIsFaster = nativeAvg < jsAvg;
  const performanceGain = ((jsAvg - nativeAvg) / jsAvg) * 100;

  return {
    testName,
    native: {
      totalTime: nativeTotalTime,
      averageTime: nativeAvg,
      minTime: nativeMin,
      maxTime: nativeMax,
      operations: iterations,
      iops: nativeIops,
      standardDeviation: nativeStdDev,
    },
    javascript: {
      totalTime: jsTotalTime,
      averageTime: jsAvg,
      minTime: jsMin,
      maxTime: jsMax,
      operations: iterations,
      iops: jsIops,
      standardDeviation: jsStdDev,
    },
    comparison: {
      speedupFactor,
      nativeIsFaster,
      performanceGain,
    },
  };
}

/**
 * Benchmark with compressed public key
 */
async function benchmarkCompressedPubKey(
  testName: string,
  iterations: number,
): Promise<BenchmarkResult> {
  const privateKey = generateRandomPrivateKey();
  const publicKeyCompressed = secp256k1.getPublicKey(privateKey, true); // compressed
  const messageHash = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    messageHash[i] = Math.floor(Math.random() * 256);
  }

  const sig = secp256k1.sign(messageHash, privateKey, { prehash: false });
  const signature = sig.toCompactRawBytes();

  // Warm up
  for (let i = 0; i < 10; i++) {
    verify(signature, messageHash, publicKeyCompressed, {
      prehash: false,
      lowS: true,
      format: 'compact',
    });
    secp256k1.verify(signature, messageHash, publicKeyCompressed, {
      prehash: false,
      lowS: true,
    });
  }

  // Benchmark native
  const nativeTimes: number[] = [];
  const nativeStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    verify(signature, messageHash, publicKeyCompressed, {
      prehash: false,
      lowS: true,
      format: 'compact',
    });
    const end = performance.now();
    nativeTimes.push(end - start);
  }

  const nativeEnd = performance.now();
  const nativeTotalTime = nativeEnd - nativeStart;

  await new Promise((resolve) => setTimeout(resolve, 10));

  // Benchmark noble
  const jsTimes: number[] = [];
  const jsStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    secp256k1.verify(signature, messageHash, publicKeyCompressed, {
      prehash: false,
      lowS: true,
    });
    const end = performance.now();
    jsTimes.push(end - start);
  }

  const jsEnd = performance.now();
  const jsTotalTime = jsEnd - jsStart;

  // Calculate statistics
  const nativeAvg = nativeTimes.reduce((a, b) => a + b, 0) / nativeTimes.length;
  const nativeMin = Math.min(...nativeTimes);
  const nativeMax = Math.max(...nativeTimes);
  const nativeStdDev = calculateStandardDeviation(nativeTimes, nativeAvg);
  const nativeIops = 1000 / nativeAvg;

  const jsAvg = jsTimes.reduce((a, b) => a + b, 0) / jsTimes.length;
  const jsMin = Math.min(...jsTimes);
  const jsMax = Math.max(...jsTimes);
  const jsStdDev = calculateStandardDeviation(jsTimes, jsAvg);
  const jsIops = 1000 / jsAvg;

  const speedupFactor = jsAvg / nativeAvg;
  const nativeIsFaster = nativeAvg < jsAvg;
  const performanceGain = ((jsAvg - nativeAvg) / jsAvg) * 100;

  return {
    testName,
    native: {
      totalTime: nativeTotalTime,
      averageTime: nativeAvg,
      minTime: nativeMin,
      maxTime: nativeMax,
      operations: iterations,
      iops: nativeIops,
      standardDeviation: nativeStdDev,
    },
    javascript: {
      totalTime: jsTotalTime,
      averageTime: jsAvg,
      minTime: jsMin,
      maxTime: jsMax,
      operations: iterations,
      iops: jsIops,
      standardDeviation: jsStdDev,
    },
    comparison: {
      speedupFactor,
      nativeIsFaster,
      performanceGain,
    },
  };
}

/**
 * Run all ECDSA verify benchmarks
 */
export async function runAllEcdsaVerifyBenchmarks(
  iterations: number = 200,
): Promise<BenchmarkResult[]> {
  const results: BenchmarkResult[] = [];

  // Test 1: Verify with pre-hashed message (32 bytes, prehash=false)
  const testData1 = generateTestData(32);
  const result1 = await benchmarkScenario(
    'Verify Pre-hashed Message (32 bytes)',
    testData1,
    iterations,
    false,
  );
  results.push(result1);

  await new Promise((resolve) => setTimeout(resolve, 50));

  // Test 2: Verify with prehash=true (message will be SHA-256 hashed)
  const testData2 = generateTestData(100);
  const result2 = await benchmarkScenario(
    'Verify with Prehash (100 byte message)',
    testData2,
    iterations,
    true,
  );
  results.push(result2);

  await new Promise((resolve) => setTimeout(resolve, 50));

  // Test 3: Verify with compressed public key
  const result3 = await benchmarkCompressedPubKey(
    'Verify with Compressed Public Key',
    iterations,
  );
  results.push(result3);

  await new Promise((resolve) => setTimeout(resolve, 50));

  // Test 4: Verify with larger message (prehash=true)
  const testData4 = generateTestData(1000);
  const result4 = await benchmarkScenario(
    'Verify with Prehash (1KB message)',
    testData4,
    iterations,
    true,
  );
  results.push(result4);

  return results;
}
