#pragma once

// OpenSSL + libsodium provide the cryptographic primitives used by security_core.
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sodium.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// CryptoEngine handles password hashing/verification and HMAC operations.
class CryptoEngine {
public:
  CryptoEngine();
  ~CryptoEngine();

  std::string hashPassword(const std::string& password) const;
  bool verifyPassword(const std::string& password, const std::string& hash) const;

  std::string computeHmacSha256(const std::string& key, const std::string& data) const;
  bool verifyHmacSha256(const std::string& key, const std::string& data, const std::string& expectedHexMac) const;

private:
  bool sodiumReady_;
};

namespace crypto_engine_detail {
// Convert binary bytes to hex for JSON-friendly output.
inline std::string toHex(const unsigned char* data, unsigned int len) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < len; ++i) {
    out << std::setw(2) << static_cast<int>(data[i]);
  }
  return out.str();
}

// Convert hex input back to bytes for verification/constant-time compare.
inline std::vector<unsigned char> fromHex(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    throw std::runtime_error("invalid hex input");
  }

  std::vector<unsigned char> bytes(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const std::string byteString = hex.substr(i, 2);
    bytes[i / 2] = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
  }
  return bytes;
}
}  // namespace crypto_engine_detail

// Initialize libsodium once so password APIs are ready to use.
inline CryptoEngine::CryptoEngine() : sodiumReady_(sodium_init() >= 0) {
  if (!sodiumReady_) {
    throw std::runtime_error("libsodium initialization failed");
  }
}

// Default destructor (no manual resource ownership in this class).
inline CryptoEngine::~CryptoEngine() = default;

// Hash plaintext password and return encoded hash string.
inline std::string CryptoEngine::hashPassword(const std::string& password) const {
  std::vector<char> out(crypto_pwhash_STRBYTES);

  if (crypto_pwhash_str_alg(
          out.data(),
          password.c_str(),
          password.size(),
          crypto_pwhash_OPSLIMIT_MODERATE,
          crypto_pwhash_MEMLIMIT_MODERATE,
          crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw std::runtime_error("password hashing failed");
  }

  return std::string(out.data());
}

// Verify plaintext password against stored hash.
inline bool CryptoEngine::verifyPassword(const std::string& password, const std::string& hash) const {
  return crypto_pwhash_str_verify(hash.c_str(), password.c_str(), password.size()) == 0;
}

// Compute HMAC-SHA256 and return hex output.
inline std::string CryptoEngine::computeHmacSha256(const std::string& key, const std::string& data) const {
  unsigned char mac[EVP_MAX_MD_SIZE] = {0};
  unsigned int macLen = 0;

  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
           reinterpret_cast<const unsigned char*>(data.data()), data.size(), mac, &macLen) == nullptr) {
    throw std::runtime_error("hmac generation failed");
  }

  return crypto_engine_detail::toHex(mac, macLen);
}

// Recompute HMAC and compare to expected value in constant time.
inline bool CryptoEngine::verifyHmacSha256(const std::string& key, const std::string& data, const std::string& expectedHexMac) const {
  const std::string computedHex = computeHmacSha256(key, data);
  const auto expected = crypto_engine_detail::fromHex(expectedHexMac);
  const auto computed = crypto_engine_detail::fromHex(computedHex);

  if (expected.size() != computed.size()) {
    return false;
  }

  return CRYPTO_memcmp(expected.data(), computed.data(), expected.size()) == 0;
}
