import { useState } from 'react';
import {
  Text,
  View,
  StyleSheet,
  ScrollView,
  Button,
  Alert,
  ActivityIndicator,
} from 'react-native';
import {
  runBenchmarkSuite,
  type BenchmarkSuite,
} from './benchmarks/publicKeyBenchmark';
import {
  testBasicFunctionality,
  testPublicKeyFormats,
  testKnownVectors,
  testNewInputVariants,
  testBigIntEdgeCases,
  testUint8ArrayEdgeCases,
  testNobleComparison,
  testErrorHandling,
} from './tests/publicKeyTests';
import { runAllNobleExtractedTests } from './tests/nobleExtractedTests';
import {
  verifyMultipleVectors,
  type VerificationResult,
} from './tests/nobleCompatibilityTests';
import { runAllHmacSha512Tests } from './tests/hmacSha512Tests';
import { runAllComprehensiveTests } from './tests/comprehensiveHmacSha512Tests';
import {
  runCompleteValidation,
  type ValidationResult,
} from './tests/rfc4231Validation';
import {
  benchmarkBIP32Scenarios,
  type BenchmarkResult as HmacBenchmarkResult,
} from './benchmarks/hmacSha512Benchmark';
import { runAllPubToAddressTests } from './tests/pubToAddressTests';
import { runAllKeccak256Tests } from './tests/keccak256Tests';
import type { TestResult } from './testUtils';
import {
  runAllPubToAddressBenchmarks,
  type BenchmarkResult as PubToAddressBenchmarkResult,
} from './benchmarks/pubToAddressBenchmark';
import {
  runAllKeccak256Benchmarks,
  type BenchmarkResult as Keccak256BenchmarkResult,
} from './benchmarks/keccak256Benchmark';
import {
  runAllEd25519Benchmarks,
  type BenchmarkResult as Ed25519BenchmarkResult,
} from './benchmarks/ed25519Benchmark';
import {
  runAllEcdsaVerifyBenchmarks,
  type BenchmarkResult as EcdsaVerifyBenchmarkResult,
} from './benchmarks/ecdsaVerifyBenchmark';
import {
  testEd25519BasicFunctionality,
  testEd25519PublicKeyFormat,
  testEd25519KnownVectors,
  testEd25519InputVariants,
  testEd25519Uint8ArrayEdgeCases,
  testEd25519NobleComparison,
  testEd25519ErrorHandling,
} from './tests/ed25519Tests';
import { runAllEd25519NobleExtractedTests } from './tests/ed25519NobleExtractedTests';
import {
  verifyMultipleEd25519Vectors,
  type Ed25519VerificationResult,
} from './tests/ed25519NobleCompatibilityTests';
import { runAllEcdsaVerifyTests } from './tests/ecdsaVerifyTests';

// Define test suite configuration
interface TestSuite {
  name: string;
  runner: () =>
    | TestResult[]
    | ValidationResult[]
    | VerificationResult[]
    | Ed25519VerificationResult[];
  key: string;
}

export default function App() {
  const [testResults, setTestResults] = useState<{
    basic: TestResult[];
    noble: TestResult[];
    hmac: TestResult[];
    comprehensive: TestResult[];
    validation: ValidationResult[];
    verification: VerificationResult[];
    pubToAddress: TestResult[];
    keccak256: TestResult[];
    ed25519: TestResult[];
    ed25519Noble: TestResult[];
    ed25519Verification: Ed25519VerificationResult[];
    ecdsaVerify: TestResult[];
  }>({
    basic: [],
    noble: [],
    hmac: [],
    comprehensive: [],
    validation: [],
    verification: [],
    pubToAddress: [],
    keccak256: [],
    ed25519: [],
    ed25519Noble: [],
    ed25519Verification: [],
    ecdsaVerify: [],
  });

  const [benchmarkResults, setBenchmarkResults] = useState<{
    suite: BenchmarkSuite | null;
    hmacSuite: HmacBenchmarkResult[] | null;
    pubToAddressSuite: PubToAddressBenchmarkResult[] | null;
    keccak256Suite: Keccak256BenchmarkResult[] | null;
    ed25519Suite: Ed25519BenchmarkResult[] | null;
    ecdsaVerifySuite: EcdsaVerifyBenchmarkResult[] | null;
  }>({
    suite: null,
    hmacSuite: null,
    pubToAddressSuite: null,
    keccak256Suite: null,
    ed25519Suite: null,
    ecdsaVerifySuite: null,
  });

  const [isRunning, setIsRunning] = useState(false);
  const [benchmarkProgress, setBenchmarkProgress] = useState<{
    current: number;
    total: number;
    testName: string;
  } | null>(null);

  // Test suites configuration
  const testSuites: TestSuite[] = [
    {
      name: 'getPublicKey',
      key: 'basic',
      runner: () => [
        ...testBasicFunctionality(),
        ...testPublicKeyFormats(),
        ...testKnownVectors(),
        ...testNewInputVariants(),
        ...testBigIntEdgeCases(),
        ...testUint8ArrayEdgeCases(),
        ...testNobleComparison(),
        ...testErrorHandling(),
      ],
    },
    {
      name: 'getPublicKey - converted test cases from noble/secp256k1',
      key: 'noble',
      runner: () => runAllNobleExtractedTests(),
    },
    {
      name: 'getPublicKey - custom noble/secp256k1 compatibility tests',
      key: 'verification',
      runner: () => verifyMultipleVectors(),
    },
    {
      name: 'HMAC-SHA512 Core Tests',
      key: 'hmac',
      runner: () => runAllHmacSha512Tests(),
    },
    {
      name: 'HMAC-SHA512 Comprehensive Tests',
      key: 'comprehensive',
      runner: () => runAllComprehensiveTests(),
    },
    {
      name: 'RFC 4231 & NIST Validation',
      key: 'validation',
      runner: () => runCompleteValidation(),
    },

    {
      name: 'pubToAddress - Address Conversion',
      key: 'pubToAddress',
      runner: () => runAllPubToAddressTests(),
    },
    {
      name: 'Keccak256 Hashing',
      key: 'keccak256',
      runner: () => runAllKeccak256Tests(),
    },
    {
      name: 'getPublicKeyEd25519',
      key: 'ed25519',
      runner: () => [
        ...testEd25519BasicFunctionality(),
        ...testEd25519PublicKeyFormat(),
        ...testEd25519KnownVectors(),
        ...testEd25519InputVariants(),
        ...testEd25519Uint8ArrayEdgeCases(),
        ...testEd25519NobleComparison(),
        ...testEd25519ErrorHandling(),
      ],
    },
    {
      name: 'getPublicKeyEd25519 - converted test cases from noble/curves',
      key: 'ed25519Noble',
      runner: () => runAllEd25519NobleExtractedTests(),
    },
    {
      name: 'getPublicKeyEd25519 - custom noble/curves compatibility tests',
      key: 'ed25519Verification',
      runner: () => verifyMultipleEd25519Vectors(),
    },
    {
      name: 'ECDSA Verify - secp256k1 signature verification',
      key: 'ecdsaVerify',
      runner: () => runAllEcdsaVerifyTests(),
    },
  ];

  const clearAllResults = () => {
    // Clear all previous results
    setTestResults({
      basic: [],
      noble: [],
      hmac: [],
      comprehensive: [],
      validation: [],
      verification: [],
      pubToAddress: [],
      keccak256: [],
      ed25519: [],
      ed25519Noble: [],
      ed25519Verification: [],
      ecdsaVerify: [],
    });
    setBenchmarkResults({
      suite: null,
      hmacSuite: null,
      pubToAddressSuite: null,
      keccak256Suite: null,
      ed25519Suite: null,
      ecdsaVerifySuite: null,
    });
  };

  // Run all tests
  const runAllTests = async () => {
    setIsRunning(true);

    clearAllResults();

    try {
      // Add a small delay to ensure the loading indicator shows
      await new Promise((resolve) => setTimeout(resolve, 100));

      const newResults = { ...testResults };

      // Run all test suites with small delays between them
      for (const suite of testSuites) {
        try {
          const results = suite.runner();
          (newResults as any)[suite.key] = results;
        } catch (error) {
          // If a test suite throws an error, create a single failed test result
          const errorResult = {
            name: `${suite.name} - Function Not Implemented`,
            message: `Error: ${
              error instanceof Error ? error.message : String(error)
            }`,
            success: false,
          };

          // Handle different result types
          if (suite.key === 'validation') {
            (newResults as any)[suite.key] = [
              {
                success: false,
                message: errorResult.name,
                expectedHex: '',
                nativeHex: '',
                nobleHex: '',
              },
            ];
          } else if (suite.key === 'verification') {
            (newResults as any)[suite.key] = [
              {
                matches: false,
                privateKey: '',
                nativeCompressed: '',
                nobleCompressed: '',
              },
            ];
          } else if (suite.key === 'ed25519Verification') {
            (newResults as any)[suite.key] = [
              {
                matches: false,
                privateKey: '',
                nativePublicKey: '',
                noblePublicKey: '',
              },
            ];
          } else {
            (newResults as any)[suite.key] = [errorResult];
          }
        }
        setTestResults({ ...newResults });

        // Small delay between test suites to allow UI updates
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    } catch (error) {
      Alert.alert('Test Error', `Failed to run tests: ${error}`);
    } finally {
      setIsRunning(false);
    }
  };

  // Benchmark functions
  const runBenchmark = async (
    type: string,
    benchmarkFn: () => Promise<any>,
  ) => {
    setIsRunning(true);

    // Clear previous test results when running benchmarks
    clearAllResults();

    try {
      const result = await benchmarkFn();
      setBenchmarkResults((prev) => ({ ...prev, [type]: result }));
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      Alert.alert(
        'Benchmark Error',
        `Failed to run ${type} benchmark: Function not implemented.\n\nError: ${errorMessage}`,
      );
      console.error(`Benchmark error for ${type}:`, error);
    } finally {
      setIsRunning(false);
      if (type === 'suite') setBenchmarkProgress(null);
    }
  };

  // Calculate test statistics
  const calculateStats = () => {
    const allResults = [
      ...testResults.basic,
      ...testResults.noble,
      ...testResults.hmac,
      ...testResults.comprehensive,
      ...testResults.validation.map((r) => ({ success: r.success })),
      ...testResults.verification.map((r) => ({ success: r.matches })),
      ...testResults.pubToAddress.map((r) => ({ success: r.success })),
      ...testResults.keccak256.map((r) => ({ success: r.success })),
      ...testResults.ed25519.map((r) => ({ success: r.success })),
      ...testResults.ed25519Noble.map((r) => ({ success: r.success })),
      ...testResults.ed25519Verification.map((r) => ({ success: r.matches })),
      ...testResults.ecdsaVerify.map((r) => ({ success: r.success })),
    ];

    const totalTests = allResults.length;
    const passedTests = allResults.filter((r) => r.success).length;
    const passRate =
      totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(1) : 0;
    const allPassed = totalTests > 0 && passedTests === totalTests;

    return { totalTests, passedTests, passRate, allPassed };
  };

  const { totalTests, passedTests, passRate, allPassed } = calculateStats();

  // Individual test suite stats
  const getTestSuiteStats = (key: string) => {
    const results = (testResults as any)[key];
    if (!results || results.length === 0) return { passed: 0, total: 0 };

    let passed = 0;
    if (key === 'validation') {
      passed = results.filter((r: ValidationResult) => r.success).length;
    } else if (key === 'verification') {
      passed = results.filter((r: VerificationResult) => r.matches).length;
    } else if (key === 'ed25519Verification') {
      passed = results.filter(
        (r: Ed25519VerificationResult) => r.matches,
      ).length;
    } else if (key === 'pubToAddress') {
      passed = results.filter((r: TestResult) => r.success).length;
    } else if (key === 'keccak256') {
      passed = results.filter((r: TestResult) => r.success).length;
    } else if (key === 'ecdsaVerify') {
      passed = results.filter((r: TestResult) => r.success).length;
    } else {
      passed = results.filter((r: TestResult) => r.success).length;
    }

    return { passed, total: results.length };
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>React Native Nitro Secp256k1</Text>
        <Text style={styles.subtitle}>Test Suite & Benchmarks</Text>

        {/* Run All Tests button */}
        <View style={styles.section}>
          <Button
            title={isRunning ? '⏳ Running All Tests...' : '🧪 Run All Tests'}
            onPress={runAllTests}
            disabled={isRunning}
          />
        </View>

        {/* Performance Benchmarks */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>⚡ Performance Benchmarks</Text>
          <View style={styles.buttonRow}>
            <View style={styles.buttonContainer}>
              <Button
                title={
                  isRunning
                    ? '⏳ Running...'
                    : '🚀 Public Key Generation Benchmark'
                }
                onPress={() =>
                  runBenchmark('suite', () =>
                    runBenchmarkSuite(
                      (current: number, total: number, testName: string) => {
                        setBenchmarkProgress({ current, total, testName });
                      },
                    ),
                  )
                }
                disabled={isRunning}
              />
            </View>
            <View style={styles.buttonContainer}>
              <Button
                title={
                  isRunning ? '⏳ Running...' : '✅ ECDSA Verify Benchmark \n'
                }
                onPress={() =>
                  runBenchmark('ecdsaVerifySuite', runAllEcdsaVerifyBenchmarks)
                }
                disabled={isRunning}
              />
            </View>
          </View>
          <View style={styles.buttonRow}>
            <View style={styles.buttonContainer}>
              <Button
                title={isRunning ? '⏳ Running...' : '🔐 HMAC Full Benchmark'}
                onPress={() =>
                  runBenchmark('hmacSuite', () => benchmarkBIP32Scenarios(200))
                }
                disabled={isRunning}
              />
            </View>
            <View style={styles.buttonContainer}>
              <Button
                title={
                  isRunning ? '⏳ Running...' : '🏠 pubToAddress Full Benchmark'
                }
                onPress={() =>
                  runBenchmark(
                    'pubToAddressSuite',
                    runAllPubToAddressBenchmarks,
                  )
                }
                disabled={isRunning}
              />
            </View>
          </View>
          <View style={styles.buttonRow}>
            <View style={styles.buttonContainer}>
              <Button
                title={
                  isRunning ? '⏳ Running...' : '🔍 Keccak256 Full Benchmark'
                }
                onPress={() =>
                  runBenchmark('keccak256Suite', runAllKeccak256Benchmarks)
                }
                disabled={isRunning}
              />
            </View>
            <View style={styles.buttonContainer}>
              <Button
                title={
                  isRunning ? '⏳ Running...' : '🔑 Ed25519 Full Benchmark'
                }
                onPress={() =>
                  runBenchmark('ed25519Suite', runAllEd25519Benchmarks)
                }
                disabled={isRunning}
              />
            </View>
          </View>
          {benchmarkProgress && (
            <Text style={styles.progressText}>
              🔄 Running: {benchmarkProgress.testName} (
              {benchmarkProgress.current}/{benchmarkProgress.total})
            </Text>
          )}
        </View>

        {/* Loading Indicator */}
        {isRunning && (
          <View style={styles.loadingSection}>
            <Text style={styles.loadingTitle}>🔄 Running All Tests...</Text>
            <Text style={styles.loadingSubtitle}>
              This may take a few moments. Please wait while we execute all test
              suites.
            </Text>
            <View style={styles.loadingIndicator}>
              <ActivityIndicator size="large" color="#ffa500" />
            </View>
          </View>
        )}

        {/* Test Overview Summary */}
        {totalTests > 0 && !isRunning && (
          <View
            style={[
              styles.section,
              allPassed ? styles.overviewSuccess : styles.overviewFailure,
            ]}
          >
            <Text style={styles.overviewTitle}>
              {allPassed ? '✅ All Tests Passed!' : '❌ Some Tests Failed'}
            </Text>
            <Text style={styles.overviewSummary}>
              Overall: {passedTests}/{totalTests} tests passed ({passRate}%)
            </Text>
            <View style={styles.overviewDetails}>
              {testSuites.map((suite) => {
                const { passed, total } = getTestSuiteStats(suite.key);
                return (
                  <Text key={suite.key} style={styles.overviewCategory}>
                    • {suite.name}: {passed}/{total}{' '}
                    {passed === total ? '✅' : '❌'}
                  </Text>
                );
              })}
            </View>
          </View>
        )}

        {/* Test Results */}
        {testSuites.map((suite) => {
          const results = (testResults as any)[suite.key];
          if (!results || results.length === 0) return null;

          const { passed, total } = getTestSuiteStats(suite.key);

          return (
            <View key={suite.key} style={styles.section}>
              <Text style={styles.sectionTitle}>
                {suite.name}: {passed}/{total} passed
              </Text>
              {results.map((result: any, index: number) => (
                <View key={index} style={styles.testResult}>
                  {suite.key === 'validation' ? (
                    <>
                      <Text
                        style={[
                          styles.testName,
                          result.success ? styles.success : styles.failure,
                        ]}
                      >
                        {result.success ? '✓' : '✗'} {result.message}
                      </Text>
                      <Text style={styles.testMessage}>
                        Expected: {result.expectedHex.slice(0, 16)}...
                      </Text>
                      <Text style={styles.testMessage}>
                        Native: {result.nativeHex.slice(0, 16)}...
                      </Text>
                      <Text style={styles.testMessage}>
                        Noble: {result.nobleHex.slice(0, 16)}...
                      </Text>
                    </>
                  ) : suite.key === 'verification' ? (
                    <>
                      <Text
                        style={[
                          styles.testName,
                          result.matches ? styles.success : styles.failure,
                        ]}
                      >
                        {result.matches ? '✓' : '✗'} Private Key:{' '}
                        {result.privateKey.slice(-8)}
                      </Text>
                      <Text style={styles.testMessage}>
                        Native Compressed:{' '}
                        {result.nativeCompressed.slice(0, 20)}...
                      </Text>
                      <Text style={styles.testMessage}>
                        Noble Compressed: {result.nobleCompressed.slice(0, 20)}
                        ...
                      </Text>
                      {!result.matches && (
                        <>
                          <Text style={[styles.testMessage, styles.failure]}>
                            ❌ MISMATCH DETECTED
                          </Text>
                          <Text style={styles.testMessage}>
                            Full Native: {result.nativeCompressed}
                          </Text>
                          <Text style={styles.testMessage}>
                            Full Noble: {result.nobleCompressed}
                          </Text>
                        </>
                      )}
                    </>
                  ) : suite.key === 'ed25519Verification' ? (
                    <>
                      <Text
                        style={[
                          styles.testName,
                          result.matches ? styles.success : styles.failure,
                        ]}
                      >
                        {result.matches ? '✓' : '✗'} Private Key:{' '}
                        {result.privateKey.slice(-8)}
                      </Text>
                      <Text style={styles.testMessage}>
                        Native Ed25519: {result.nativePublicKey.slice(0, 20)}...
                      </Text>
                      <Text style={styles.testMessage}>
                        Noble Ed25519: {result.noblePublicKey.slice(0, 20)}
                        ...
                      </Text>
                      {!result.matches && (
                        <>
                          <Text style={[styles.testMessage, styles.failure]}>
                            ❌ MISMATCH DETECTED
                          </Text>
                          <Text style={styles.testMessage}>
                            Full Native: {result.nativePublicKey}
                          </Text>
                          <Text style={styles.testMessage}>
                            Full Noble: {result.noblePublicKey}
                          </Text>
                        </>
                      )}
                    </>
                  ) : suite.key === 'pubToAddress' ? (
                    <>
                      <Text
                        style={[
                          styles.testName,
                          result.success ? styles.success : styles.failure,
                        ]}
                      >
                        {result.success ? '✓' : '✗'} {result.name}
                      </Text>
                      <Text style={styles.testMessage}>{result.message}</Text>
                    </>
                  ) : suite.key === 'keccak256' ? (
                    <>
                      <Text
                        style={[
                          styles.testName,
                          result.success ? styles.success : styles.failure,
                        ]}
                      >
                        {result.success ? '✓' : '✗'} {result.name}
                      </Text>
                      <Text style={styles.testMessage}>{result.message}</Text>
                    </>
                  ) : (
                    <>
                      <Text
                        style={[
                          styles.testName,
                          result.success ? styles.success : styles.failure,
                        ]}
                      >
                        {result.success ? '✓' : '✗'} {result.name}
                      </Text>
                      <Text style={styles.testMessage}>{result.message}</Text>
                    </>
                  )}
                </View>
              ))}
            </View>
          );
        })}

        {/* Benchmark Results */}
        {benchmarkResults.suite && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>
              🚀 Public Key Generation Benchmark
            </Text>
            <View style={styles.benchmarkSummary}>
              <Text style={styles.benchmarkSummaryTitle}>
                📊 Performance Overview
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                Tests: {benchmarkResults.suite.summary.totalTests} • Native
                Wins: {benchmarkResults.suite.summary.nativeWins} • JS Wins:{' '}
                {benchmarkResults.suite.summary.jsWins}
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                Average Speedup:{' '}
                {benchmarkResults.suite.summary.averageSpeedup.toFixed(2)}x
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                Overall Native IOPS:{' '}
                {benchmarkResults.suite.summary.overallIopsNative.toFixed(0)} •
                JS IOPS:{' '}
                {benchmarkResults.suite.summary.overallIopsJs.toFixed(0)}
              </Text>
            </View>
            <Text style={styles.sectionSubtitle}>Individual Test Results:</Text>
            {benchmarkResults.suite.results.map(
              (result: any, index: number) => (
                <View key={index} style={styles.benchmarkResult}>
                  <Text style={styles.benchmarkTitle}>
                    {index % 2 === 0 ? '🔑' : '🔓'} {result.testName}
                  </Text>
                  <View style={styles.benchmarkMetrics}>
                    <Text style={styles.benchmarkDetails}>
                      🚀 Native: {result.native.averageTime.toFixed(3)}ms avg •{' '}
                      {result.native.iops.toFixed(0)} ops/sec
                    </Text>
                    <Text style={styles.benchmarkDetails}>
                      📜 JavaScript: {result.javascript.averageTime.toFixed(3)}
                      ms avg • {result.javascript.iops.toFixed(0)} ops/sec
                    </Text>
                    <Text
                      style={[
                        styles.benchmarkComparison,
                        result.comparison.nativeIsFaster
                          ? styles.success
                          : styles.failure,
                      ]}
                    >
                      ⚡ {result.comparison.speedupFactor.toFixed(2)}x{' '}
                      {result.comparison.nativeIsFaster ? 'faster' : 'slower'} •{' '}
                      {result.comparison.percentageDifference.toFixed(1)}%
                      difference
                    </Text>
                    <Text style={styles.benchmarkRange}>
                      📈 Range: {result.native.minTime.toFixed(3)}ms -{' '}
                      {result.native.maxTime.toFixed(3)}ms (Native) |{' '}
                      {result.javascript.minTime.toFixed(3)}ms -{' '}
                      {result.javascript.maxTime.toFixed(3)}ms (JS)
                    </Text>
                    <Text style={styles.benchmarkStats}>
                      📊 Std Dev: ±{result.native.standardDeviation.toFixed(3)}
                      ms (Native) • ±
                      {result.javascript.standardDeviation.toFixed(3)}ms (JS)
                    </Text>
                  </View>
                </View>
              ),
            )}
          </View>
        )}

        {benchmarkResults.hmacSuite && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>
              🔐 HMAC-SHA512 BIP32 Benchmark Suite
            </Text>
            <View style={styles.benchmarkSummary}>
              <Text style={styles.benchmarkSummaryTitle}>
                📊 Performance Overview
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                {benchmarkResults.hmacSuite.length} test scenarios completed
              </Text>
            </View>
            <Text style={styles.sectionSubtitle}>Individual Test Results:</Text>
            {benchmarkResults.hmacSuite.map((result: any, index: number) => (
              <View key={index} style={styles.benchmarkResult}>
                <Text style={styles.benchmarkTitle}>
                  {index === 0 ? '🔑' : index === 1 ? '🔒' : '🌱'}{' '}
                  {result.testName}
                </Text>
                <View style={styles.benchmarkMetrics}>
                  <Text style={styles.benchmarkDetails}>
                    🚀 Native: {result.native.averageTime.toFixed(3)}ms avg •{' '}
                    {result.native.iops.toFixed(0)} ops/sec
                  </Text>
                  <Text style={styles.benchmarkDetails}>
                    📜 JavaScript: {result.javascript.averageTime.toFixed(3)}ms
                    avg • {result.javascript.iops.toFixed(0)} ops/sec
                  </Text>
                  <Text
                    style={[
                      styles.benchmarkComparison,
                      result.comparison.nativeIsFaster
                        ? styles.success
                        : styles.failure,
                    ]}
                  >
                    ⚡ {result.comparison.speedupFactor.toFixed(2)}x{' '}
                    {result.comparison.nativeIsFaster ? 'faster' : 'slower'} •{' '}
                    {result.comparison.percentageImprovement.toFixed(1)}%
                    improvement
                  </Text>
                  <Text style={styles.benchmarkRange}>
                    📈 Range: {result.native.minTime.toFixed(3)}ms -{' '}
                    {result.native.maxTime.toFixed(3)}ms (Native) |{' '}
                    {result.javascript.minTime.toFixed(3)}ms -{' '}
                    {result.javascript.maxTime.toFixed(3)}ms (JS)
                  </Text>
                </View>
              </View>
            ))}
          </View>
        )}

        {benchmarkResults.pubToAddressSuite && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>
              🏠 Public Key → Address Benchmark Suite
            </Text>
            <View style={styles.benchmarkSummary}>
              <Text style={styles.benchmarkSummaryTitle}>
                📊 Performance Overview
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                {benchmarkResults.pubToAddressSuite.length} conversion scenarios
                tested
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                Average Speedup:{' '}
                {(
                  benchmarkResults.pubToAddressSuite.reduce(
                    (sum: number, r: any) => sum + r.comparison.speedupFactor,
                    0,
                  ) / benchmarkResults.pubToAddressSuite.length
                ).toFixed(2)}
                x
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                All Faster:{' '}
                {benchmarkResults.pubToAddressSuite.every(
                  (r: any) => r.comparison.nativeIsFaster,
                )
                  ? '✅ Yes'
                  : '❌ No'}
              </Text>
            </View>
            <Text style={styles.sectionSubtitle}>Individual Test Results:</Text>
            {benchmarkResults.pubToAddressSuite.map(
              (result: any, index: number) => {
                const getTestIcon = (testName: string) => {
                  if (testName.includes('64-byte')) return '📏';
                  if (testName.includes('65-byte')) return '🔧';
                  if (testName.includes('Multiple')) return '🔄';
                  if (testName.includes('Mixed')) return '🎯';
                  return '🏠';
                };

                return (
                  <View key={index} style={styles.benchmarkResult}>
                    <Text style={styles.benchmarkTitle}>
                      {getTestIcon(result.testName)} {result.testName}
                    </Text>
                    <View style={styles.benchmarkMetrics}>
                      <Text style={styles.benchmarkDetails}>
                        🚀 Native: {result.native.averageTime.toFixed(3)}ms avg
                        • {result.native.iops.toFixed(0)} ops/sec
                      </Text>
                      <Text style={styles.benchmarkDetails}>
                        📜 JavaScript:{' '}
                        {result.javascript.averageTime.toFixed(3)}ms avg •{' '}
                        {result.javascript.iops.toFixed(0)} ops/sec
                      </Text>
                      <Text
                        style={[
                          styles.benchmarkComparison,
                          result.comparison.nativeIsFaster
                            ? styles.success
                            : styles.failure,
                        ]}
                      >
                        ⚡ {result.comparison.speedupFactor.toFixed(2)}x{' '}
                        {result.comparison.nativeIsFaster ? 'faster' : 'slower'}{' '}
                        • {result.comparison.performanceGain.toFixed(1)}%
                        improvement
                      </Text>
                      <Text style={styles.benchmarkRange}>
                        📈 Range: {result.native.minTime.toFixed(3)}ms -{' '}
                        {result.native.maxTime.toFixed(3)}ms (Native) |{' '}
                        {result.javascript.minTime.toFixed(3)}ms -{' '}
                        {result.javascript.maxTime.toFixed(3)}ms (JS)
                      </Text>
                      <Text style={styles.benchmarkStats}>
                        📊 Std Dev: ±
                        {result.native.standardDeviation.toFixed(3)}ms (Native)
                        • ±{result.javascript.standardDeviation.toFixed(3)}ms
                        (JS)
                      </Text>
                    </View>
                  </View>
                );
              },
            )}
          </View>
        )}

        {benchmarkResults.keccak256Suite && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>
              🔍 Keccak256 Hashing Benchmark Suite
            </Text>
            <View style={styles.benchmarkSummary}>
              <Text style={styles.benchmarkSummaryTitle}>
                📊 Performance Overview
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                {benchmarkResults.keccak256Suite.length} hashing scenarios
                tested
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                Average Speedup:{' '}
                {(
                  benchmarkResults.keccak256Suite.reduce(
                    (sum: number, r: any) => sum + r.comparison.speedupFactor,
                    0,
                  ) / benchmarkResults.keccak256Suite.length
                ).toFixed(2)}
                x
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                All Faster:{' '}
                {benchmarkResults.keccak256Suite.every(
                  (r: any) => r.comparison.nativeIsFaster,
                )
                  ? '✅ Yes'
                  : '❌ No'}
              </Text>
            </View>
            <Text style={styles.sectionSubtitle}>Individual Test Results:</Text>
            {benchmarkResults.keccak256Suite.map(
              (result: any, index: number) => {
                const getTestIcon = (testName: string) => {
                  if (testName.includes('Small')) return '📝';
                  if (testName.includes('Private')) return '🔑';
                  if (testName.includes('Public')) return '🔓';
                  if (testName.includes('BIP32')) return '🌱';
                  if (testName.includes('Transaction')) return '💳';
                  if (testName.includes('ETH Address')) return '⚡';
                  if (testName.includes('Hex vs Bytes')) return '🔄';
                  return '🔍';
                };

                return (
                  <View key={index} style={styles.benchmarkResult}>
                    <Text style={styles.benchmarkTitle}>
                      {getTestIcon(result.testName)} {result.testName}
                    </Text>
                    <View style={styles.benchmarkMetrics}>
                      <Text style={styles.benchmarkDetails}>
                        🚀 Native: {result.native.averageTime.toFixed(3)}ms avg
                        • {result.native.iops.toFixed(0)} ops/sec
                      </Text>
                      <Text style={styles.benchmarkDetails}>
                        📜 Noble: {result.javascript.averageTime.toFixed(3)}ms
                        avg • {result.javascript.iops.toFixed(0)} ops/sec
                      </Text>
                      <Text
                        style={[
                          styles.benchmarkComparison,
                          result.comparison.nativeIsFaster
                            ? styles.success
                            : styles.failure,
                        ]}
                      >
                        ⚡ {result.comparison.speedupFactor.toFixed(2)}x{' '}
                        {result.comparison.nativeIsFaster ? 'faster' : 'slower'}{' '}
                        • {result.comparison.performanceGain.toFixed(1)}%
                        improvement
                      </Text>
                      <Text style={styles.benchmarkRange}>
                        📈 Range: {result.native.minTime.toFixed(3)}ms -{' '}
                        {result.native.maxTime.toFixed(3)}ms (Native) |{' '}
                        {result.javascript.minTime.toFixed(3)}ms -{' '}
                        {result.javascript.maxTime.toFixed(3)}ms (Noble)
                      </Text>
                      <Text style={styles.benchmarkStats}>
                        📊 Std Dev: ±
                        {result.native.standardDeviation.toFixed(3)}ms (Native)
                        • ±{result.javascript.standardDeviation.toFixed(3)}ms
                        (Noble)
                      </Text>
                    </View>
                  </View>
                );
              },
            )}
          </View>
        )}

        {benchmarkResults.ed25519Suite && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>
              🔑 Ed25519 Public Key Generation Benchmark Suite
            </Text>
            <View style={styles.benchmarkSummary}>
              <Text style={styles.benchmarkSummaryTitle}>
                📊 Performance Overview
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                {benchmarkResults.ed25519Suite.length} key generation scenarios
                tested
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                Average Speedup:{' '}
                {(
                  benchmarkResults.ed25519Suite.reduce(
                    (sum: number, r: any) => sum + r.comparison.speedupFactor,
                    0,
                  ) / benchmarkResults.ed25519Suite.length
                ).toFixed(2)}
                x
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                All Faster:{' '}
                {benchmarkResults.ed25519Suite.every(
                  (r: any) => r.comparison.nativeIsFaster,
                )
                  ? '✅ Yes'
                  : '❌ No'}
              </Text>
            </View>
            <Text style={styles.sectionSubtitle}>Individual Test Results:</Text>
            {benchmarkResults.ed25519Suite.map((result: any, index: number) => {
              const getTestIcon = (testName: string) => {
                if (testName.includes('Random')) return '🎲';
                if (testName.includes('RFC')) return '📖';
                return '🔑';
              };

              return (
                <View key={index} style={styles.benchmarkResult}>
                  <Text style={styles.benchmarkTitle}>
                    {getTestIcon(result.testName)} {result.testName}
                  </Text>
                  <View style={styles.benchmarkMetrics}>
                    <Text style={styles.benchmarkDetails}>
                      🚀 Native: {result.native.averageTime.toFixed(3)}ms avg •{' '}
                      {result.native.iops.toFixed(0)} ops/sec
                    </Text>
                    <Text style={styles.benchmarkDetails}>
                      📜 Noble: {result.javascript.averageTime.toFixed(3)}ms avg
                      • {result.javascript.iops.toFixed(0)} ops/sec
                    </Text>
                    <Text
                      style={[
                        styles.benchmarkComparison,
                        result.comparison.nativeIsFaster
                          ? styles.success
                          : styles.failure,
                      ]}
                    >
                      ⚡ {result.comparison.speedupFactor.toFixed(2)}x{' '}
                      {result.comparison.nativeIsFaster ? 'faster' : 'slower'} •{' '}
                      {result.comparison.performanceGain.toFixed(1)}%
                      improvement
                    </Text>
                    <Text style={styles.benchmarkRange}>
                      📈 Range: {result.native.minTime.toFixed(3)}ms -{' '}
                      {result.native.maxTime.toFixed(3)}ms (Native) |{' '}
                      {result.javascript.minTime.toFixed(3)}ms -{' '}
                      {result.javascript.maxTime.toFixed(3)}ms (Noble)
                    </Text>
                    <Text style={styles.benchmarkStats}>
                      📊 Std Dev: ±{result.native.standardDeviation.toFixed(3)}
                      ms (Native) • ±
                      {result.javascript.standardDeviation.toFixed(3)}ms (Noble)
                    </Text>
                  </View>
                </View>
              );
            })}
          </View>
        )}

        {benchmarkResults.ecdsaVerifySuite && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>
              ✅ ECDSA Verify Benchmark Suite
            </Text>
            <View style={styles.benchmarkSummary}>
              <Text style={styles.benchmarkSummaryTitle}>
                📊 Performance Overview
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                {benchmarkResults.ecdsaVerifySuite.length} verification
                scenarios tested
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                Average Speedup:{' '}
                {(
                  benchmarkResults.ecdsaVerifySuite.reduce(
                    (sum: number, r: any) => sum + r.comparison.speedupFactor,
                    0,
                  ) / benchmarkResults.ecdsaVerifySuite.length
                ).toFixed(2)}
                x
              </Text>
              <Text style={styles.benchmarkSummaryText}>
                All Faster:{' '}
                {benchmarkResults.ecdsaVerifySuite.every(
                  (r: any) => r.comparison.nativeIsFaster,
                )
                  ? '✅ Yes'
                  : '❌ No'}
              </Text>
            </View>
            <Text style={styles.sectionSubtitle}>Individual Test Results:</Text>
            {benchmarkResults.ecdsaVerifySuite.map(
              (result: any, index: number) => {
                const getTestIcon = (testName: string) => {
                  if (testName.includes('Pre-hashed')) return '🔐';
                  if (testName.includes('Prehash')) return '📝';
                  if (testName.includes('Compressed')) return '🗜️';
                  return '✅';
                };

                return (
                  <View key={index} style={styles.benchmarkResult}>
                    <Text style={styles.benchmarkTitle}>
                      {getTestIcon(result.testName)} {result.testName}
                    </Text>
                    <View style={styles.benchmarkMetrics}>
                      <Text style={styles.benchmarkDetails}>
                        🚀 Native: {result.native.averageTime.toFixed(3)}ms avg
                        • {result.native.iops.toFixed(0)} ops/sec
                      </Text>
                      <Text style={styles.benchmarkDetails}>
                        📜 Noble: {result.javascript.averageTime.toFixed(3)}ms
                        avg • {result.javascript.iops.toFixed(0)} ops/sec
                      </Text>
                      <Text
                        style={[
                          styles.benchmarkComparison,
                          result.comparison.nativeIsFaster
                            ? styles.success
                            : styles.failure,
                        ]}
                      >
                        ⚡ {result.comparison.speedupFactor.toFixed(2)}x{' '}
                        {result.comparison.nativeIsFaster ? 'faster' : 'slower'}{' '}
                        • {result.comparison.performanceGain.toFixed(1)}%
                        improvement
                      </Text>
                      <Text style={styles.benchmarkRange}>
                        📈 Range: {result.native.minTime.toFixed(3)}ms -{' '}
                        {result.native.maxTime.toFixed(3)}ms (Native) |{' '}
                        {result.javascript.minTime.toFixed(3)}ms -{' '}
                        {result.javascript.maxTime.toFixed(3)}ms (Noble)
                      </Text>
                      <Text style={styles.benchmarkStats}>
                        📊 Std Dev: ±
                        {result.native.standardDeviation.toFixed(3)}ms (Native)
                        • ±{result.javascript.standardDeviation.toFixed(3)}ms
                        (Noble)
                      </Text>
                    </View>
                  </View>
                );
              },
            )}
          </View>
        )}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  content: {
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 10,
    color: '#333',
  },
  subtitle: {
    fontSize: 16,
    textAlign: 'center',
    marginBottom: 30,
    color: '#666',
  },
  section: {
    backgroundColor: 'white',
    padding: 15,
    marginBottom: 20,
    borderRadius: 8,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#333',
  },
  sectionSubtitle: {
    fontSize: 16,
    fontWeight: '600',
    marginTop: 15,
    marginBottom: 10,
    color: '#444',
  },
  buttonRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 10,
  },
  buttonContainer: {
    flex: 1,
    marginHorizontal: 5,
  },
  progressText: {
    fontSize: 12,
    color: '#666',
    textAlign: 'center',
    marginTop: 10,
  },
  testResult: {
    marginBottom: 10,
    paddingBottom: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  testName: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 5,
  },
  testMessage: {
    fontSize: 12,
    color: '#666',
    fontFamily: 'monospace',
  },
  benchmarkResult: {
    marginBottom: 15,
    paddingBottom: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  benchmarkTitle: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 5,
    color: '#333',
  },
  benchmarkDetails: {
    fontSize: 12,
    color: '#666',
    fontFamily: 'monospace',
    marginBottom: 2,
  },
  benchmarkText: {
    fontSize: 12,
    color: '#333',
    fontFamily: 'monospace',
    backgroundColor: '#f8f8f8',
    padding: 10,
    borderRadius: 4,
    marginBottom: 10,
  },
  success: {
    color: '#4CAF50',
  },
  failure: {
    color: '#F44336',
  },
  info: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
    lineHeight: 20,
  },
  overviewSuccess: {
    backgroundColor: '#f0fff4',
    borderLeftWidth: 4,
    borderLeftColor: '#4CAF50',
  },
  overviewFailure: {
    backgroundColor: '#fff5f5',
    borderLeftWidth: 4,
    borderLeftColor: '#F44336',
  },
  overviewTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 10,
    color: '#333',
  },
  overviewSummary: {
    fontSize: 16,
    fontWeight: '600',
    textAlign: 'center',
    marginBottom: 15,
    color: '#333',
  },
  overviewDetails: {
    backgroundColor: '#f8f9fa',
    padding: 10,
    borderRadius: 6,
  },
  overviewCategory: {
    fontSize: 14,
    fontWeight: '500',
    marginBottom: 5,
    color: '#444',
    fontFamily: 'monospace',
  },
  loadingSection: {
    backgroundColor: '#fff8dc',
    padding: 20,
    marginBottom: 20,
    borderRadius: 8,
    borderLeftWidth: 4,
    borderLeftColor: '#ffa500',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  loadingTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 10,
    color: '#333',
  },
  loadingSubtitle: {
    fontSize: 14,
    textAlign: 'center',
    marginBottom: 15,
    color: '#666',
    lineHeight: 20,
  },
  loadingIndicator: {
    alignItems: 'center',
  },
  benchmarkSummary: {
    backgroundColor: '#f0f8ff',
    padding: 12,
    borderRadius: 8,
    marginBottom: 15,
    borderLeftWidth: 4,
    borderLeftColor: '#4682b4',
  },
  benchmarkSummaryTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 8,
    color: '#2c3e50',
  },
  benchmarkSummaryText: {
    fontSize: 13,
    color: '#555',
    fontFamily: 'monospace',
    marginBottom: 3,
  },
  benchmarkMetrics: {
    marginTop: 8,
    backgroundColor: '#fafafa',
    padding: 8,
    borderRadius: 6,
  },
  benchmarkComparison: {
    fontSize: 14,
    fontWeight: 'bold',
    marginTop: 8,
    marginBottom: 5,
    paddingVertical: 4,
    paddingHorizontal: 8,
    borderRadius: 4,
    backgroundColor: 'rgba(255,255,255,0.8)',
  },
  benchmarkRange: {
    fontSize: 11,
    color: '#777',
    marginTop: 6,
    fontFamily: 'monospace',
    backgroundColor: '#f8f8f8',
    padding: 4,
    borderRadius: 3,
  },
  benchmarkStats: {
    fontSize: 11,
    color: '#777',
    marginTop: 4,
    fontFamily: 'monospace',
    backgroundColor: '#f8f8f8',
    padding: 4,
    borderRadius: 3,
  },
});
