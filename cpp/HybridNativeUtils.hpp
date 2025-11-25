#pragma once

#include "HybridNativeUtilsSpec.hpp"

namespace margelo::nitro::metamask_nativeutils {

class HybridNativeUtils : public HybridNativeUtilsSpec {
public:
  HybridNativeUtils() : HybridObject(TAG) {}

public:
  double multiply(double a, double b) override;
  std::shared_ptr<ArrayBuffer> toPublicKey(const std::string& privateKey, bool isCompressed) override;
  std::shared_ptr<ArrayBuffer> toPublicKeyFromBytes(const std::shared_ptr<ArrayBuffer>& privateKey, bool isCompressed) override;
  std::shared_ptr<ArrayBuffer> getPublicKeyEd25519(const std::string& privateKey) override;
  std::shared_ptr<ArrayBuffer> getPublicKeyEd25519FromBytes(const std::shared_ptr<ArrayBuffer>& privateKey) override;
  std::shared_ptr<ArrayBuffer> keccak256FromBytes(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> pubToAddress(const std::shared_ptr<ArrayBuffer>& pubKey, bool sanitize = false) override;
  std::shared_ptr<ArrayBuffer> hmacSha512(const std::shared_ptr<ArrayBuffer>& key, const std::shared_ptr<ArrayBuffer>& data) override;
};

} // namespace margelo::nitro::metamask_nativeutils
