project(metamask_nativeutils)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME metamask_nativeutils)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# Configure secp256k1 build options
set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "Disable secp256k1 recovery module")
set(SECP256K1_ENABLE_MODULE_ECDH OFF CACHE BOOL "Disable secp256k1 ECDH module")
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF CACHE BOOL "Disable secp256k1 Schnorr signature module")
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS OFF CACHE BOOL "Disable secp256k1 extrakeys module")
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "Build secp256k1 tests")
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "Build secp256k1 benchmark")
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "Build secp256k1 examples")
set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "Disable shared library to avoid conflicts")
set(SECP256K1_INSTALL OFF CACHE BOOL "Disable installation")

# Add secp256k1 as a subdirectory (will be built as static lib)
add_subdirectory(${CMAKE_SOURCE_DIR}/../cpp/secp256k1 secp256k1)

# Define C++ library and add all sources
add_library(${PACKAGE_NAME} SHARED 
    src/main/cpp/cpp-adapter.cpp
    ../cpp/HybridNativeUtils.cpp
    ../cpp/hex_utils.cpp
)

# Add Nitrogen specs :)
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/metamask_nativeutils+autolinking.cmake)

# Set up local includes
include_directories("src/main/cpp" "../cpp" "../cpp/secp256k1/include" "../cpp/secp256k1/src")

find_library(LOG_LIB log)

# Link all libraries together
target_link_libraries(
        ${PACKAGE_NAME}
        secp256k1
        ${LOG_LIB}
        android # <-- Android core
)
