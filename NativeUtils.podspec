require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "NativeUtils"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/MetaMask/native-utils.git", :tag => "#{s.version}" }


  s.source_files = [
    "ios/**/*.{swift}",
    "ios/**/*.{m,mm}",
    "cpp/*.{hpp,cpp}",
    "cpp/*.{h,c}",
    "cpp/secp256k1/src/*.{h,c}",
  ]

  s.exclude_files = [
    # Exclude secp256k1 test files
    "cpp/secp256k1/src/tests.c",
    "cpp/secp256k1/src/tests_exhaustive.c",
    "cpp/secp256k1/src/ctime_tests.c",
    "cpp/secp256k1/src/bench.c",
    "cpp/secp256k1/src/bench_internal.c",
    "cpp/secp256k1/src/bench_ecmult.c",
    "cpp/secp256k1/src/testrand.h",
    "cpp/secp256k1/src/testutil.h",
    "cpp/secp256k1/src/selftest.h",
    "cpp/secp256k1/src/**/tests_impl.h",
    "cpp/secp256k1/src/**/bench_impl.h",
  ]

  s.public_header_files = [
    "cpp/secp256k1/include/secp256k1.h",
  ]

  s.header_dir = "secp256k1"
  s.header_mappings_dir = "cpp/secp256k1/include"

  s.pod_target_xcconfig = {
    # C++ compiler flags, mainly for folly.
    "GCC_PREPROCESSOR_DEFINITIONS" => "$(inherited) FOLLY_NO_CONFIG FOLLY_CFG_NO_COROUTINES USE_ECMULT_STATIC_PRECOMPUTATION USE_FIELD_10X26 USE_SCALAR_8X32 ECMULT_WINDOW_SIZE=15 ECMULT_GEN_PREC_BITS=4",
    "HEADER_SEARCH_PATHS" => "$(inherited) $(PODS_TARGET_SRCROOT)/cpp/secp256k1 $(PODS_TARGET_SRCROOT)/cpp/secp256k1/include $(PODS_TARGET_SRCROOT)/cpp/secp256k1/src",
    "OTHER_CFLAGS" => "$(inherited) -DUSE_ECMULT_STATIC_PRECOMPUTATION -DUSE_FIELD_10X26 -DUSE_SCALAR_8X32 -DECMULT_WINDOW_SIZE=15 -DECMULT_GEN_PREC_BITS=4",
    "CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES" => "YES"
  }

  s.dependency 'React-jsi'
  s.dependency 'React-callinvoker'

  load 'nitrogen/generated/ios/NativeUtils+autolinking.rb'
  add_nitrogen_files(s)

  install_modules_dependencies(s)
end
