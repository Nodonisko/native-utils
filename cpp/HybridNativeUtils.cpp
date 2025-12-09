#include "HybridNativeUtils.hpp"
#include "secp256k1/include/secp256k1.h"
#include "hex_utils.hpp"
#include "botan_conditional.h"
#include <stdexcept>
#include <mutex>

namespace margelo::nitro::metamask_nativeutils {

// Static global context for maximum performance.
// Made const and initialized with a call-once guard for thread safety.
static std::once_flag g_ctx_once;
static const secp256k1_context* g_ctx = nullptr;

static void initializeContext() {
    std::call_once(g_ctx_once, []() {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    });

    if (!g_ctx) {
        throw std::runtime_error("Failed to initialize secp256k1 context");
    }
}

// Helper that wraps secp256k1_ec_pubkey_serialize and enforces the expected output length.
// libsecp256k1 treats the length parameter as an in/out value: on input it is the buffer
// capacity, on output it is the actual number of bytes written. We defensively verify that
// the actual length matches the format we requested (33 or 65 bytes) so that future changes
// in libsecp256k1 cannot cause us to read uninitialized or truncated public key data.
static void serializeSecp256k1PubkeyChecked(
    const secp256k1_pubkey* pubkey,
    uint8_t* output,
    size_t expectedLen,
    unsigned int flags) {
  size_t outputLen = expectedLen;
  if (!secp256k1_ec_pubkey_serialize(g_ctx, output, &outputLen, pubkey, flags)) {
    throw std::runtime_error("Failed to serialize public key");
  }
  if (outputLen != expectedLen) {
    throw std::runtime_error("Unexpected public key length from secp256k1");
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

  unsigned int flags = isCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

  serializeSecp256k1PubkeyChecked(&pubkey, data, keySize, flags);
  
  return buffer;
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::toPublicKey(const std::string& privateKey, bool isCompressed) {
  // Must be exactly 64 characters (32 bytes)
  if (privateKey.length() != 64) {
      throw std::runtime_error("Private key must be 64 hex characters (32 bytes)");
  }
  
  uint8_t privateKeyBytes[32];
  hexToBytes(privateKey, privateKeyBytes, 32);
  
  return generatePublicKeyFromBytes(privateKeyBytes, isCompressed);
}

std::shared_ptr<ArrayBuffer> HybridNativeUtils::toPublicKeyFromBytes(const std::shared_ptr<ArrayBuffer>& privateKey, bool isCompressed) {
  // Validate input size (must be exactly 32 bytes for secp256k1)
  if (privateKey->size() != 32) {
      throw std::runtime_error("Private key must be 32 bytes");
  }
  
  // Get the private key bytes directly
  const uint8_t* privateKeyBytes = static_cast<const uint8_t*>(privateKey->data());
  
  return generatePublicKeyFromBytes(privateKeyBytes, isCompressed);
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
  if (privateKey->size() != 32) {
    throw std::runtime_error("Private key must be 32 bytes");
  }
  const uint8_t* seed = static_cast<const uint8_t*>(privateKey->data());
  
  return generateEd25519PublicKeyFromBytes(seed);
}

static std::shared_ptr<ArrayBuffer> keccak256Hash(const uint8_t* dataBytes, size_t dataLen) {
  auto hasher = Botan::HashFunction::create("Keccak-1600(256)");
  if (!hasher) {
    throw std::runtime_error("Failed to create Keccak-256 hasher");
  }

  hasher->update(dataBytes, dataLen);

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
      serializeSecp256k1PubkeyChecked(
          &parsedPubkey,
          uncompressedKey,
          65,
          SECP256K1_EC_UNCOMPRESSED);
      
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

static void sha256Hash(const uint8_t* data, size_t dataLen, uint8_t* output) {
  auto hasher = Botan::HashFunction::create("SHA-256");
  if (!hasher) {
    throw std::runtime_error("Failed to create SHA-256 hasher");
  }
  hasher->update(data, dataLen);
  hasher->final(output);
}

bool HybridNativeUtils::ecdsaVerify(
    const std::shared_ptr<ArrayBuffer>& signature,
    const std::shared_ptr<ArrayBuffer>& message,
    const std::shared_ptr<ArrayBuffer>& pubKey,
    bool prehash,
    bool lowS,
    const std::string& format) {
  initializeContext();
  
  const uint8_t* sigBytes = static_cast<const uint8_t*>(signature->data());
  size_t sigLen = signature->size();
  const uint8_t* msgBytes = static_cast<const uint8_t*>(message->data());
  size_t msgLen = message->size();
  const uint8_t* pubKeyBytes = static_cast<const uint8_t*>(pubKey->data());
  size_t pubKeyLen = pubKey->size();
  
  // Parse the signature based on format
  secp256k1_ecdsa_signature sig;
  
  if (format == "compact") {
    if (sigLen != 64) {
      return false;
    }
    if (!secp256k1_ecdsa_signature_parse_compact(g_ctx, &sig, sigBytes)) {
      return false;
    }
  } else if (format == "recovered") {
    // Recovered format is 65 bytes: recovery byte + 64 byte compact signature
    if (sigLen != 65) {
      return false;
    }
    // Skip the first byte (recovery byte) and parse the remaining 64 bytes as compact
    if (!secp256k1_ecdsa_signature_parse_compact(g_ctx, &sig, sigBytes + 1)) {
      return false;
    }
  } else if (format == "der") {
    // Defensive checks for DER format to prevent crashes on malformed input
    // Valid secp256k1 DER signatures are typically 70-72 bytes, max ~73 bytes
    // Minimum is 8 bytes (2 for SEQUENCE header + 2x3 for minimal integers)
    // Strict DER validation prevents parsing ambiguities and improves security
    if (sigLen < 8 || sigLen > 73) {
      return false;
    }
    // Must start with SEQUENCE tag (0x30)
    if (sigBytes[0] != 0x30) {
      return false;
    }
    // The length byte should indicate remaining length
    // For short form (which all valid ECDSA sigs use), it should be sigLen - 2
    if (sigBytes[1] != sigLen - 2) {
      return false;
    }
    if (!secp256k1_ecdsa_signature_parse_der(g_ctx, &sig, sigBytes, sigLen)) {
      return false;
    }
  } else {
    throw std::runtime_error("Invalid signature format. Must be 'compact', 'recovered', or 'der'");
  }
  
  // Check if signature has high S and handle accordingly
  // secp256k1_ecdsa_signature_normalize returns 1 if the signature had high S (was normalized)
  // We always normalize the signature for verification (both (r,s) and (r,n-s) are mathematically valid)
  // but only reject high-S when lowS=true
  bool wasHighS = secp256k1_ecdsa_signature_normalize(g_ctx, &sig, &sig) == 1;
  
  // Reject high-S signatures if lowS enforcement is requested
  if (lowS && wasHighS) {
    return false;
  }
  
  // Compute message hash if prehash is true
  uint8_t msgHash[32];
  if (prehash) {
    sha256Hash(msgBytes, msgLen, msgHash);
  } else {
    // Message should already be a 32-byte hash
    if (msgLen != 32) {
      return false;
    }
    memcpy(msgHash, msgBytes, 32);
  }
  
  // Parse the public key
  secp256k1_pubkey parsedPubKey;
  if (!secp256k1_ec_pubkey_parse(g_ctx, &parsedPubKey, pubKeyBytes, pubKeyLen)) {
    return false;
  }
  
  // Verify the signature
  return secp256k1_ecdsa_verify(g_ctx, &sig, msgHash, &parsedPubKey) == 1;
}

} // namespace margelo::nitro::metamask_nativeutils