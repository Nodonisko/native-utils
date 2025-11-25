#include "HybridNativeUtils.hpp"
#include "secp256k1_wrapper.h"
#include "hex_utils.hpp"
#include "botan_conditional.h"
#include <stdexcept>

namespace margelo::nitro::metamask_nativeutils {

// Static global context for maximum performance
static secp256k1_context* g_ctx = nullptr;

// Initialize context once (thread-safe)
static void initializeContext() {
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    }
}


// Common function to generate public key from raw private key bytes
static std::shared_ptr<ArrayBuffer> generatePublicKeyFromBytes(const uint8_t* privateKeyBytes, bool isCompressed) {
  initializeContext();
  
  // Use secp256k1's built-in validation (checks if key is not 0 and < curve order)
  if (!secp256k1_ec_seckey_verify(g_ctx, privateKeyBytes)) {
      throw std::runtime_error("Private key is invalid");
  }
  
  // Create public key from private key
  secp256k1_pubkey pubkey;
  if (!secp256k1_ec_pubkey_create(g_ctx, &pubkey, privateKeyBytes)) {
      throw std::runtime_error("Failed to create public key from private key");
  }
  
  // Serialize the public key
  size_t keySize = isCompressed ? 33 : 65;
  auto buffer = ArrayBuffer::allocate(keySize);
  auto data = static_cast<uint8_t*>(buffer->data());
  
  size_t outputLen = keySize;
  unsigned int flags = isCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
  
  if (!secp256k1_ec_pubkey_serialize(g_ctx, data, &outputLen, &pubkey, flags)) {
      throw std::runtime_error("Failed to serialize public key");
  }
  
  return buffer;
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::toPublicKey(const std::string& privateKey, bool isCompressed) {
  std::string hex = privateKey;
  
  // Must be exactly 64 characters (32 bytes)
  if (hex.length() != 64) {
      throw std::runtime_error("Private key must be 64 hex characters (32 bytes)");
  }
  
  // Convert hex to bytes with validation
  uint8_t seckey[32];
  hexToBytes(hex, seckey, 32);
  
  return generatePublicKeyFromBytes(seckey, isCompressed);
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::toPublicKeyFromBytes(const std::shared_ptr<ArrayBuffer>& privateKey, bool isCompressed) {
  // Validate input size (must be exactly 32 bytes for secp256k1)
  if (privateKey->size() != 32) {
      throw std::runtime_error("Private key must be 32 bytes");
  }
  
  // Get the private key bytes directly
  const uint8_t* seckey = static_cast<const uint8_t*>(privateKey->data());
  
  return generatePublicKeyFromBytes(seckey, isCompressed);
}

// Common function to generate ed25519 public key from private key bytes (seed)
static std::shared_ptr<ArrayBuffer> generateEd25519PublicKeyFromBytes(const uint8_t* privateKeyBytes) {
  auto buffer = ArrayBuffer::allocate(32);
  uint8_t* publicKey = static_cast<uint8_t*>(buffer->data());
  uint8_t secretKey[64];
  
  Botan::ed25519_gen_keypair(publicKey, secretKey, privateKeyBytes);
  
  return buffer;
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::getPublicKeyEd25519(const std::string& privateKey) {
  uint8_t seed[32];
  hexToBytes(privateKey, seed, 32);
  
  return generateEd25519PublicKeyFromBytes(seed);
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::getPublicKeyEd25519FromBytes(const std::shared_ptr<ArrayBuffer>& privateKey) {
  const uint8_t* seed = static_cast<const uint8_t*>(privateKey->data());
  
  return generateEd25519PublicKeyFromBytes(seed);
}

static std::shared_ptr<ArrayBuffer> keccak256Hash(const uint8_t* dataBytes, size_t dataLen) {
  auto hasher = Botan::HashFunction::create("Keccak-1600(256)");
  if (!hasher) {
    throw std::runtime_error("Failed to create Keccak-256 hasher");
  }

  hasher->update(dataBytes, dataLen);

  // Convert hex string to bytes
  auto result = ArrayBuffer::allocate(32);
  hasher->final(static_cast<uint8_t*>(result->data()));

  return result;
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::keccak256FromBytes(const std::shared_ptr<ArrayBuffer>& data) {
  // Get the data bytes
  const uint8_t* dataBytes = static_cast<const uint8_t*>(data->data());
  size_t dataLen = data->size();
  
  return keccak256Hash(dataBytes, dataLen);
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::pubToAddress(const std::shared_ptr<ArrayBuffer>& pubKey, bool sanitize) {
  initializeContext();
  
  const uint8_t* pubKeyBytes = static_cast<const uint8_t*>(pubKey->data());
  size_t pubKeySize = pubKey->size();
  
  // Buffer to hold the 64-byte uncompressed public key (without 0x04 prefix)
  uint8_t uncompressedPubKeyBytes[64];
  
  // Handle sanitization - convert various formats to 64-byte uncompressed
  if (sanitize && pubKeySize != 64) {
      secp256k1_pubkey parsedPubkey;
      
      // Parse SEC1-encoded public key with libsecp256k1 to ensure validity
      if (!secp256k1_ec_pubkey_parse(g_ctx, &parsedPubkey, pubKeyBytes, pubKeySize)) {
          throw std::runtime_error("Invalid public key format");
      }
      
      // Serialize to uncompressed format (65 bytes)
      uint8_t uncompressedKey[65];
      size_t outputLen = 65;
      if (!secp256k1_ec_pubkey_serialize(g_ctx, uncompressedKey, &outputLen, &parsedPubkey, SECP256K1_EC_UNCOMPRESSED)) {
          throw std::runtime_error("Failed to serialize public key");
      }
      
      // Skip the 0x04 prefix byte for keccak hashing
      memcpy(uncompressedPubKeyBytes, uncompressedKey + 1, 64);
      pubKeyBytes = uncompressedPubKeyBytes;
      pubKeySize = 64;
  } else {
      if (pubKeySize != 64) {
          throw std::runtime_error("Expected pubKey to be of length 64");
      }
  }
  
  auto hashResult = keccak256Hash(pubKeyBytes, 64);
  
  // Return the last 20 bytes (Ethereum address)
  auto result = ArrayBuffer::allocate(20);
  memcpy(result->data(), static_cast<const uint8_t*>(hashResult->data()) + 12, 20);
  
  return result;
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::hmacSha512(const std::shared_ptr<ArrayBuffer>& key, const std::shared_ptr<ArrayBuffer>& data) {
  // Get key and data pointers
  const uint8_t* keyBytes = static_cast<const uint8_t*>(key->data());
  const uint8_t* dataBytes = static_cast<const uint8_t*>(data->data());

  const auto keyLen = key->size();

  auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");

  mac->set_key(keyBytes, keyLen);
  mac->update(dataBytes, data->size());

  auto buffer = ArrayBuffer::allocate(mac->output_length());
  mac->final(static_cast<uint8_t*>(buffer->data()));

  return buffer;
}

double HybridNativeUtils::multiply(double a, double b) {
  return a * b;
}

} // namespace margelo::nitro::metamask_nativeutils