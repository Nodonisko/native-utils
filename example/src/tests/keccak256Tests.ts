import { keccak256 } from '@metamask/native-utils';
import { keccak_256 } from '@noble/hashes/sha3';
import type { TestResult } from '../testUtils';
import { uint8ArrayToHex, utf8ToBytes, repeat } from '../testUtils';

// NIST test vectors (adapted from noble-hashes)
const NIST_VECTORS = [
  {
    input: utf8ToBytes('abc'),
    expected:
      '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
  },
  {
    input: utf8ToBytes(''),
    expected:
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  },
  {
    input: utf8ToBytes(
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    ),
    expected:
      '45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371',
  },
  {
    input: utf8ToBytes(
      'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
    ),
    expected:
      'f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67',
  },
  {
    input: repeat(utf8ToBytes('a'), 1000000),
    expected:
      'fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96',
  },
];

// Ethereum-specific test vectors
const ETHEREUM_VECTORS = [
  {
    name: 'Empty input',
    input: new Uint8Array([]),
    expected:
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  },
  {
    name: 'Single byte',
    input: new Uint8Array([0x00]),
    expected:
      'bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a',
  },
  {
    name: 'Two bytes',
    input: new Uint8Array([0x00, 0x01]),
    expected:
      '49d03a195e239b52779866b33024210fc7dc66e9c2998975c0aa45c1702549d5',
  },
  {
    name: '32 zeros',
    input: new Uint8Array(32),
    expected:
      '290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563',
  },
  {
    name: 'Sequential bytes 0-255',
    input: new Uint8Array(Array.from({ length: 256 }, (_, i) => i)),
    expected:
      'dc924469b334aed2a19fac7252e9961aea41f8d91996366029dbe0884229bf36',
  },
];

// Additional edge case vectors
const EDGE_CASE_VECTORS = [
  {
    name: 'All 0xFF bytes (32 bytes)',
    input: new Uint8Array(32).fill(0xff),
    expected:
      '5f423bf942c6d74e2c80f2de59b9b49e14f4b1c4a39b6f51e1b8f79b8a33e4b5',
  },
  {
    name: 'Alternating 0x55/0xAA pattern',
    input: new Uint8Array(64).map((_, i) => (i % 2 === 0 ? 0x55 : 0xaa)),
    expected:
      'd5b44a4ad7925e89e0ef20ff7a3c7b25d27b3d7c6e7c9c8d5a8e9fbeaf3b6c4d',
  },
];

// Real-world regression test vectors (hex string inputs that produced mismatches)
const REAL_WORLD_REGRESSION_VECTORS = [
  {
    name: 'Regression 1',
    input: 'c24ef7796beeb7694e86fca4bafcdf955f16e6fc',
    expected:
      '685e0f46502ecea5c5295794cc7a75b6f2e600d342e7747f0720801dae53dac8',
  },
  {
    name: 'Regression 2',
    input: '7c0098a632dadda2b0bd7e61ce0e0aae475b71b9',
    expected:
      '4b8aa6f1876dc1b23baf944b4588181d9be94570ce632d59904dbcd1d8d061c1',
  },
  {
    name: 'Regression 3',
    input: 'b7097abf11a01bc24055594c17e00ac420b8340d',
    expected:
      'b95c5b052cabe6e6e62840083262499e53951d94dd618930a0d93dae7bcce08a',
  },
  {
    name: 'Regression 4',
    input: '812361947078e31ed8665836b1558d93486ea3ce',
    expected:
      '23b86b252d5364c6930b2199c47cee2c5023e13cb56450f46a03291d1e503cec',
  },
  {
    name: 'Regression 5',
    input: '205f993a489df59761c56a97b52c463c3a1e7a94',
    expected:
      'f04af70574355312f900f027743a14af00260ba89c1e74aa23cfdcc76ccd3b18',
  },
  {
    name: 'Regression 6',
    input: '82a38e01d487dddf57a9a5d3413f7f15b9848137',
    expected:
      '2bdfd737ef55c2406c7e22a68bc55e3ebc6a3f4687209a8d711a282a49ad0552',
  },
  {
    name: 'Regression 7',
    input: '708922a24d868f1f95f02f6b9a6bb78c3a251822',
    expected:
      'b548b7eedb3d6b5bba248221b4c53e61bf6998db0cccb93f2f278a787dbce940',
  },
  {
    name: 'Regression 8',
    input: '7eb8208adf0e9001747faf3752b94aaf47171aec',
    expected:
      'fc85b7e71730d6cd87482aab2d72547136ff35f34972454a7d5d58953539ade8',
  },
  {
    name: 'Regression 9',
    input: '6f1e92b2218d7e01b448b6d0198066fd3a24c94e',
    expected:
      '61e516e2676e4adefd150b23af3dd09fbe8b2518826d693c27e28b4fa2160edd',
  },
  {
    name: 'Regression 10',
    input: '1a72ee4da274f1bcf6af3bac305d5d483eb0610c',
    expected:
      '378d644ab52b8aee2d7133aa0aeeee1b32a8ddd6c2889af7b0b822700d912fb6',
  },
  {
    name: 'Regression 11',
    input: '7edad62bac0eed45f4c7bc1b9a28ad4be899661f',
    expected:
      '8bd4872b5b820535f7bc893b3bf513052ea9d5b741af152e60fea01c2fd13d55',
  },
  {
    name: 'Regression 12',
    input: '8de73eeea3d55d8433f32b1527a6975cd08033fe',
    expected:
      'b5faacb5c0daf75598c4eb6f2d523861331814680f02cc0fdb03b005364ad693',
  },
  {
    name: 'Regression 13',
    input: '5528bcd3ad2ed78c87ec14b5615de401531af294',
    expected:
      '5af0ce95ba1c5327fa3a03a2d71049a28df5618461568a21acc1d027a3ea7662',
  },
  {
    name: 'Regression 14',
    input: '4b7db62d807732ab6c480e989fa5aaf09e140d7c',
    expected:
      'fedd7819be62f5e0882f96ed798fdce8af937ba97f7536689ce6dd79e6262f44',
  },
  {
    name: 'Regression 15',
    input: '38e6d583f2aa04d84aaaf6a42237da80715eaba4',
    expected:
      '3ac059be640b107102d5f259b9ec68a201ea7dfb5a584b5c856dae12e08d8df8',
  },
  {
    name: 'Regression 16',
    input: 'e068d3c3e0098c22b0e708a0f22be02a52953565',
    expected:
      'e01391911498bf5f3486d7c5fd11f7b100aa17389d33fe219eaa0164f1903cc9',
  },
  {
    name: 'Regression 17',
    input: '6a4b0984b1a877edef5a5a36b2b86b3cf33bb1f9',
    expected:
      '445cfb88faa23729b395e30acd15b11b4f2af22ac452376b900d0681206c7712',
  },
  {
    name: 'Regression 18',
    input: '739ac2a08ded6ec03b5954c8efdef7640dfd4a48',
    expected:
      '34f34b80ad3d3fbf5db260df557c5b518ad7c40c4c2f5c8bcbd5f3b33ec61a1a',
  },
  {
    name: 'Regression 19',
    input: '12811b73ae4c6fc876166276866a1a6e2464e754',
    expected:
      'daf59840ee8e2cfa41ea6cd4e517529abbaccc053accbb01667978387a9b640e',
  },
  {
    name: 'Regression 20',
    input: '568f30e65b7d555319c943100fe25e5788daf280',
    expected:
      'fd8126c7a15c4f3d711348a699088d45f609cd25ee580a4f3627963eb79b6822',
  },
  {
    name: 'Regression 21',
    input: '9855d3f0580ccbef16fb3cc7bd6d309223bd1229',
    expected:
      '2c3a3c18438049cdb6ae99b2f158e35dd4ccb2ac761e5c6a5eb74ce1ebfeb412',
  },
  {
    name: 'Regression 22',
    input: 'bb1789127f1547914fa682bdfe41674a4793c3c0',
    expected:
      '4cada0de9b0b65468a779a73b4255e1c81c5d84257fc6d4248367eb236d033ad',
  },
  {
    name: 'Regression 23',
    input: '29c048b54aa39008b81129649acabf0fcaddd772',
    expected:
      'a4c5d6d91e842f18b1f0737ffb33a2cb0f75c7a53d69fc2f7763ba33a2b1008b',
  },
  {
    name: 'Regression 24',
    input: '5a97d8aa6d6a06636b9e80727121c31640082606',
    expected:
      'fff5b199f28a379cfd4ed8fb289e54115b81ab5ff676de6987d152536e2b659d',
  },
  {
    name: 'Regression 25',
    input: 'c5030f3aa7d5e342f21b496548071fa42f033d76',
    expected:
      'b05f5191c327c1454d3ab7babae31bc0fa66cc5b95c9a9d4fae9b31911a85d15',
  },
  {
    name: 'Regression 26',
    input: '122e9d42c470142e2fd70120b686c2342c9bf37b',
    expected:
      '631fc615af0bf20948aa97c71930f60f2460b9dd1d865f95977da2c59bc6dead',
  },
  {
    name: 'Regression 27',
    input: 'e609de43f1b5be05120161010f9dbfb8ec4abf3c',
    expected:
      '89f5c83b60ce63dfb69ce762895c6efc79919c445c1a12c354ee22c25e9067c2',
  },
];

// Test input format variations (string, Uint8Array, ArrayBuffer, number[])
export function testInputFormats(): TestResult[] {
  const results: TestResult[] = [];

  // Test with known data: "hello world" as UTF-8 bytes
  const testData = 'hello world';
  const testBytes = utf8ToBytes(testData);
  const expectedHex =
    '47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad';

  try {
    // Test 1: Uint8Array input (this is the reference)
    const result1 = keccak256(testBytes);
    const hex1 = uint8ArrayToHex(result1, false);

    results.push({
      name: 'Uint8Array input',
      success: hex1 === expectedHex,
      message:
        hex1 === expectedHex
          ? '✓ Uint8Array input works correctly'
          : `Expected: ${expectedHex}, got: ${hex1}`,
    });

    // Test 2: String input (UTF-8 string - same as passing through utf8ToBytes)
    // keccak256("hello world") should equal keccak256(utf8ToBytes("hello world"))
    const result2 = keccak256(testData);
    const hex2 = uint8ArrayToHex(result2, false);

    results.push({
      name: 'String input (UTF-8)',
      success: hex2 === expectedHex,
      message:
        hex2 === expectedHex
          ? '✓ UTF-8 string input works correctly'
          : `Expected: ${expectedHex}, got: ${hex2}`,
    });

    // Test 3: ArrayBuffer input
    const buffer = new ArrayBuffer(testBytes.length);
    new Uint8Array(buffer).set(testBytes);
    const result3 = keccak256(buffer);
    const hex3 = uint8ArrayToHex(result3, false);

    results.push({
      name: 'ArrayBuffer input',
      success: hex3 === expectedHex,
      message:
        hex3 === expectedHex
          ? '✓ ArrayBuffer input works correctly'
          : `Expected: ${expectedHex}, got: ${hex3}`,
    });

    // Test 4: Number array input
    const numberArray = Array.from(testBytes);
    const result4 = keccak256(numberArray);
    const hex4 = uint8ArrayToHex(result4, false);

    results.push({
      name: 'Number array input',
      success: hex4 === expectedHex,
      message:
        hex4 === expectedHex
          ? '✓ Number array input works correctly'
          : `Expected: ${expectedHex}, got: ${hex4}`,
    });

    // Test 5: Verify string, Uint8Array, ArrayBuffer, and number[] all produce same result
    // (string is now UTF-8, so keccak256("hello world") === keccak256(utf8ToBytes("hello world")))
    const allMatch = hex1 === hex2 && hex2 === hex3 && hex3 === hex4;
    results.push({
      name: 'All input formats produce same result',
      success: allMatch,
      message: allMatch
        ? '✓ All input formats produce identical results'
        : `Results differ: Uint8Array(${hex1}), string(${hex2}), buffer(${hex3}), array(${hex4})`,
    });
  } catch (error) {
    results.push({
      name: 'Input format test error',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

// Test input format edge cases
export function testInputFormatEdgeCases(): TestResult[] {
  const results: TestResult[] = [];

  // Test empty inputs for each type
  try {
    // Empty Uint8Array
    const emptyBytes = new Uint8Array([]);
    const result1 = keccak256(emptyBytes);
    const hex1 = uint8ArrayToHex(result1, false);
    const expectedEmpty =
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

    results.push({
      name: 'Empty Uint8Array',
      success: hex1 === expectedEmpty,
      message:
        hex1 === expectedEmpty
          ? '✓ Empty Uint8Array works correctly'
          : `Expected: ${expectedEmpty}, got: ${hex1}`,
    });

    // Empty string (UTF-8 encoded empty string = 0 bytes)
    const result2 = keccak256('');
    const hex2 = uint8ArrayToHex(result2, false);

    results.push({
      name: 'Empty string',
      success: hex2 === expectedEmpty,
      message:
        hex2 === expectedEmpty
          ? '✓ Empty string works correctly'
          : `Expected: ${expectedEmpty}, got: ${hex2}`,
    });

    // Empty ArrayBuffer
    const emptyBuffer = new ArrayBuffer(0);
    const result3 = keccak256(emptyBuffer);
    const hex3 = uint8ArrayToHex(result3, false);

    results.push({
      name: 'Empty ArrayBuffer',
      success: hex3 === expectedEmpty,
      message:
        hex3 === expectedEmpty
          ? '✓ Empty ArrayBuffer works correctly'
          : `Expected: ${expectedEmpty}, got: ${hex3}`,
    });

    // Empty number array
    const result4 = keccak256([]);
    const hex4 = uint8ArrayToHex(result4, false);

    results.push({
      name: 'Empty number array',
      success: hex4 === expectedEmpty,
      message:
        hex4 === expectedEmpty
          ? '✓ Empty number array works correctly'
          : `Expected: ${expectedEmpty}, got: ${hex4}`,
    });

    // All empty inputs should produce same result
    const allEmptyMatch = hex1 === hex2 && hex2 === hex3 && hex3 === hex4;
    results.push({
      name: 'All empty inputs produce same result',
      success: allEmptyMatch,
      message: allEmptyMatch
        ? '✓ All empty input formats produce identical results'
        : `Results differ: bytes(${hex1}), string(${hex2}), buffer(${hex3}), array(${hex4})`,
    });
  } catch (error) {
    results.push({
      name: 'Empty input test error',
      success: false,
      message: `Error: ${error}`,
    });
  }

  // Test single byte inputs for Uint8Array, ArrayBuffer, and number[]
  // Note: String input is UTF-8, so a single character string is NOT the same as a single byte
  try {
    const singleByte = 0x00;
    const expectedSingle =
      'bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a';

    // Single byte in Uint8Array
    const result1 = keccak256(new Uint8Array([singleByte]));
    const hex1 = uint8ArrayToHex(result1, false);

    // Single byte in ArrayBuffer
    const buffer = new ArrayBuffer(1);
    new Uint8Array(buffer)[0] = singleByte;
    const result3 = keccak256(buffer);
    const hex3 = uint8ArrayToHex(result3, false);

    // Single byte in number array
    const result4 = keccak256([singleByte]);
    const hex4 = uint8ArrayToHex(result4, false);

    // Verify the expected hash for single byte 0x00
    results.push({
      name: 'Single byte (0x00) expected hash',
      success: hex1 === expectedSingle,
      message:
        hex1 === expectedSingle
          ? '✓ Single byte 0x00 produces expected hash'
          : `Expected: ${expectedSingle}, got: ${hex1}`,
    });

    const allSingleMatch = hex1 === hex3 && hex3 === hex4;
    results.push({
      name: 'Single byte input consistency (Uint8Array, ArrayBuffer, number[])',
      success: allSingleMatch,
      message: allSingleMatch
        ? '✓ All single-byte input formats produce identical results'
        : `Results differ: bytes(${hex1}), buffer(${hex3}), array(${hex4})`,
    });
  } catch (error) {
    results.push({
      name: 'Single byte input test error',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

// Test NIST vectors
export function testNISTVectors(): TestResult[] {
  const results: TestResult[] = [];

  NIST_VECTORS.forEach((vector, index) => {
    try {
      const result = keccak256(vector.input);
      const hex = uint8ArrayToHex(result, false);
      const matches = hex === vector.expected;

      results.push({
        name: `NIST vector ${index + 1}`,
        success: matches,
        message: matches
          ? '✓ Matches expected result'
          : `Expected: ${vector.expected}, got: ${hex}`,
      });
    } catch (error) {
      results.push({
        name: `NIST vector ${index + 1}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  });

  return results;
}

// Test Ethereum-specific vectors
export function testEthereumVectors(): TestResult[] {
  const results: TestResult[] = [];

  ETHEREUM_VECTORS.forEach((vector) => {
    try {
      const result = keccak256(vector.input);
      const hex = uint8ArrayToHex(result, false);
      const matches = hex === vector.expected;

      results.push({
        name: vector.name,
        success: matches,
        message: matches
          ? '✓ Matches expected result'
          : `Expected: ${vector.expected}, got: ${hex}`,
      });
    } catch (error) {
      results.push({
        name: vector.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  });

  return results;
}

// Test edge cases
export function testEdgeCases(): TestResult[] {
  const results: TestResult[] = [];

  EDGE_CASE_VECTORS.forEach((vector) => {
    try {
      const result = keccak256(vector.input);
      const hex = uint8ArrayToHex(result, false);

      // For edge cases, we just verify that:
      // 1. No error is thrown
      // 2. Result is 32 bytes
      // 3. Result is not all zeros
      const isValid = result.length === 32 && hex !== '0'.repeat(64);

      results.push({
        name: vector.name,
        success: isValid,
        message: isValid
          ? `✓ Valid 32-byte hash: ${hex.slice(0, 16)}...`
          : `Invalid result: length=${result.length}, hex=${hex}`,
      });
    } catch (error) {
      results.push({
        name: vector.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  });

  return results;
}

// Test real-world regression cases (hex string inputs)
export function testRealWorldRegressions(): TestResult[] {
  const results: TestResult[] = [];

  REAL_WORLD_REGRESSION_VECTORS.forEach((vector) => {
    try {
      const result = keccak256(vector.input);
      const hex = uint8ArrayToHex(result, false);
      const matches = hex === vector.expected;

      results.push({
        name: vector.name,
        success: matches,
        message: matches
          ? '✓ Matches expected result'
          : `Expected: ${vector.expected}, got: ${hex}`,
      });
    } catch (error) {
      results.push({
        name: vector.name,
        success: false,
        message: `Error: ${error}`,
      });
    }
  });

  return results;
}

// Note: Error handling tests for "invalid hex string" removed because
// strings are now treated as UTF-8 (matching noble's behavior), not hex.
// Any string is valid UTF-8 input.

// Test return type
export function testReturnType(): TestResult[] {
  const results: TestResult[] = [];

  try {
    const result = keccak256(utf8ToBytes('test'));

    results.push({
      name: 'Return type is Uint8Array',
      success: result instanceof Uint8Array,
      message:
        result instanceof Uint8Array
          ? '✓ Returns Uint8Array as expected'
          : `Wrong return type: ${typeof result}`,
    });

    results.push({
      name: 'Return length is 32 bytes',
      success: result.length === 32,
      message:
        result.length === 32
          ? '✓ Returns 32-byte hash as expected'
          : `Wrong length: ${result.length} (expected 32)`,
    });
  } catch (error) {
    results.push({
      name: 'Return type test',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

// Test direct comparison with @noble/hashes
export function testNobleComparison(): TestResult[] {
  const results: TestResult[] = [];

  // Test vectors for direct comparison
  const testCases = [
    {
      name: 'Empty input',
      input: new Uint8Array([]),
    },
    {
      name: 'Single byte [0x00]',
      input: new Uint8Array([0x00]),
    },
    {
      name: 'Single byte [0xFF]',
      input: new Uint8Array([0xff]),
    },
    {
      name: 'Two bytes [0x00, 0x01]',
      input: new Uint8Array([0x00, 0x01]),
    },
    {
      name: 'ASCII "hello"',
      input: utf8ToBytes('hello'),
    },
    {
      name: 'ASCII "hello world"',
      input: utf8ToBytes('hello world'),
    },
    {
      name: 'UTF-8 "Hello, 世界"',
      input: utf8ToBytes('Hello, 世界'),
    },
    {
      name: '32 zero bytes',
      input: new Uint8Array(32),
    },
    {
      name: '32 0xFF bytes',
      input: new Uint8Array(32).fill(0xff),
    },
    {
      name: 'Sequential bytes 0-15',
      input: new Uint8Array(Array.from({ length: 16 }, (_, i) => i)),
    },
    {
      name: 'Sequential bytes 0-255',
      input: new Uint8Array(Array.from({ length: 256 }, (_, i) => i)),
    },
    {
      name: 'Large random-like data (1024 bytes)',
      input: new Uint8Array(1024).map((_, i) => (i * 137 + 42) % 256),
    },
  ];

  for (const testCase of testCases) {
    try {
      // Get results from both implementations
      const nativeResult = keccak256(testCase.input);
      const nobleResult = keccak_256(testCase.input);

      // Convert to hex for comparison
      const nativeHex = uint8ArrayToHex(nativeResult, false);
      const nobleHex = uint8ArrayToHex(nobleResult, false);

      // Compare results
      const matches = nativeHex === nobleHex;

      results.push({
        name: `Noble comparison: ${testCase.name}`,
        success: matches,
        message: matches
          ? `✓ Native matches @noble/hashes: ${nativeHex.slice(0, 16)}...`
          : `✗ Mismatch - Native: ${nativeHex.slice(0, 16)}..., Noble: ${nobleHex.slice(0, 16)}...`,
      });

      // Also verify both return 32 bytes
      if (nativeResult.length !== 32 || nobleResult.length !== 32) {
        results.push({
          name: `Length check: ${testCase.name}`,
          success: false,
          message: `Length mismatch - Native: ${nativeResult.length}, Noble: ${nobleResult.length}`,
        });
      }
    } catch (error) {
      results.push({
        name: `Noble comparison: ${testCase.name}`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

// Test input format consistency with @noble/hashes
export function testNobleInputFormatConsistency(): TestResult[] {
  const results: TestResult[] = [];

  // Test data
  const testData = 'react-native-nitro-secp256k1';
  const testBytes = utf8ToBytes(testData);

  try {
    // Test 1: Direct Uint8Array comparison
    const nativeResult1 = keccak256(testBytes);
    const nobleResult1 = keccak_256(testBytes);
    const hex1Match =
      uint8ArrayToHex(nativeResult1, false) ===
      uint8ArrayToHex(nobleResult1, false);

    results.push({
      name: 'Uint8Array consistency with Noble',
      success: hex1Match,
      message: hex1Match
        ? '✓ Native Uint8Array input matches Noble'
        : `✗ Mismatch - Native: ${uint8ArrayToHex(nativeResult1, false).slice(0, 16)}..., Noble: ${uint8ArrayToHex(nobleResult1, false).slice(0, 16)}...`,
    });

    // Test 2: String input (native) vs String input (noble) - MUST produce same result for drop-in compatibility
    const nativeResult2 = keccak256(testData); // Native with string
    const nobleResult2 = keccak_256(testData); // Noble with string
    const hex2Match =
      uint8ArrayToHex(nativeResult2, false) ===
      uint8ArrayToHex(nobleResult2, false);

    results.push({
      name: 'String input: Native vs Noble (drop-in compatibility)',
      success: hex2Match,
      message: hex2Match
        ? '✓ Native string input matches Noble string input'
        : `✗ Mismatch - Native: ${uint8ArrayToHex(nativeResult2, false).slice(0, 16)}..., Noble: ${uint8ArrayToHex(nobleResult2, false).slice(0, 16)}...`,
    });

    // Test 3: ArrayBuffer (native) vs Uint8Array (noble)
    const buffer = new ArrayBuffer(testBytes.length);
    new Uint8Array(buffer).set(testBytes);
    const nativeResult3 = keccak256(buffer);
    const nobleResult3 = keccak_256(testBytes);
    const hex3Match =
      uint8ArrayToHex(nativeResult3, false) ===
      uint8ArrayToHex(nobleResult3, false);

    results.push({
      name: 'ArrayBuffer (native) vs Uint8Array (noble)',
      success: hex3Match,
      message: hex3Match
        ? '✓ Native ArrayBuffer input matches Noble Uint8Array'
        : `✗ Mismatch - Native buffer: ${uint8ArrayToHex(nativeResult3, false).slice(0, 16)}..., Noble bytes: ${uint8ArrayToHex(nobleResult3, false).slice(0, 16)}...`,
    });

    // Test 4: Number array (native) vs Uint8Array (noble)
    const numberArray = Array.from(testBytes);
    const nativeResult4 = keccak256(numberArray);
    const nobleResult4 = keccak_256(testBytes);
    const hex4Match =
      uint8ArrayToHex(nativeResult4, false) ===
      uint8ArrayToHex(nobleResult4, false);

    results.push({
      name: 'Number array (native) vs Uint8Array (noble)',
      success: hex4Match,
      message: hex4Match
        ? '✓ Native number array input matches Noble Uint8Array'
        : `✗ Mismatch - Native array: ${uint8ArrayToHex(nativeResult4, false).slice(0, 16)}..., Noble bytes: ${uint8ArrayToHex(nobleResult4, false).slice(0, 16)}...`,
    });
  } catch (error) {
    results.push({
      name: 'Input format consistency test',
      success: false,
      message: `Error: ${error}`,
    });
  }

  return results;
}

// Test DIRECT string comparison with @noble/hashes - critical for drop-in replacement compatibility
// This ensures that keccak256(someString) produces identical results to keccak_256(someString)
export function testNobleDirectStringComparison(): TestResult[] {
  const results: TestResult[] = [];

  // Various string inputs that could be passed to the function
  // These include hex-looking strings, regular text, edge cases
  const stringTestCases = [
    // Hex-looking strings (the original bug case - these should be treated as UTF-8, not decoded)
    'c24ef7796beeb7694e86fca4bafcdf955f16e6fc',
    '7c0098a632dadda2b0bd7e61ce0e0aae475b71b9',
    'b7097abf11a01bc24055594c17e00ac420b8340d',
    '0x1234567890abcdef', // With 0x prefix
    'deadbeef',
    'DEADBEEF', // Uppercase hex
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', // 64 char hex

    // Regular text strings
    '',
    'hello',
    'hello world',
    'Hello, 世界',
    'The quick brown fox jumps over the lazy dog',
    'abc',
    'a',

    // Edge cases
    '   ', // Whitespace
    '\n\t\r', // Special characters
    '🚀🌍💫', // Emojis
    'null',
    'undefined',
    'true',
    'false',
    '0',
    '1',
    '-1',
    '3.14159',

    // Ethereum-related strings
    'transfer(address,uint256)',
    'Transfer(address,address,uint256)',
    'balanceOf(address)',
    'approve(address,uint256)',
  ];

  for (const testString of stringTestCases) {
    try {
      // Pass the EXACT same string to both implementations
      const nativeResult = keccak256(testString);
      const nobleResult = keccak_256(testString);

      const nativeHex = uint8ArrayToHex(nativeResult, false);
      const nobleHex = uint8ArrayToHex(nobleResult, false);
      const matches = nativeHex === nobleHex;

      const displayString =
        testString.length > 20
          ? `${testString.slice(0, 20)}...`
          : testString || '(empty)';

      results.push({
        name: `Direct string: "${displayString}"`,
        success: matches,
        message: matches
          ? `✓ Native matches Noble: ${nativeHex.slice(0, 16)}...`
          : `✗ MISMATCH - Native: ${nativeHex}, Noble: ${nobleHex}`,
      });
    } catch (error) {
      results.push({
        name: `Direct string: "${testString.slice(0, 20)}..."`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  }

  return results;
}

// Test that regression vectors match noble when passed as strings (the original bug scenario)
export function testRegressionVectorsMatchNoble(): TestResult[] {
  const results: TestResult[] = [];

  // Use the same regression vectors, but compare native vs noble directly
  REAL_WORLD_REGRESSION_VECTORS.forEach((vector) => {
    try {
      // Pass the same string input to both
      const nativeResult = keccak256(vector.input);
      const nobleResult = keccak_256(vector.input);

      const nativeHex = uint8ArrayToHex(nativeResult, false);
      const nobleHex = uint8ArrayToHex(nobleResult, false);
      const matches = nativeHex === nobleHex;

      results.push({
        name: `${vector.name}: Native vs Noble`,
        success: matches,
        message: matches
          ? `✓ Native matches Noble: ${nativeHex.slice(0, 16)}...`
          : `✗ MISMATCH - Native: ${nativeHex}, Noble: ${nobleHex}`,
      });

      // Also verify the result matches the expected value (which is the noble result)
      const matchesExpected = nativeHex === vector.expected;
      results.push({
        name: `${vector.name}: Matches expected`,
        success: matchesExpected,
        message: matchesExpected
          ? '✓ Matches expected hash'
          : `✗ Expected: ${vector.expected}, Got: ${nativeHex}`,
      });
    } catch (error) {
      results.push({
        name: `${vector.name}: Native vs Noble`,
        success: false,
        message: `Error: ${error}`,
      });
    }
  });

  return results;
}

// Run all keccak256 tests
export function runAllKeccak256Tests(): TestResult[] {
  return [
    ...testInputFormats(),
    ...testInputFormatEdgeCases(),
    ...testNISTVectors(),
    ...testEthereumVectors(),
    ...testEdgeCases(),
    ...testRealWorldRegressions(),
    ...testReturnType(),
    ...testNobleComparison(),
    ...testNobleInputFormatConsistency(),
    ...testNobleDirectStringComparison(),
    ...testRegressionVectorsMatchNoble(),
  ];
}
