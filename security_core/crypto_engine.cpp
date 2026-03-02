#include "crypto_engine.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sodium.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {
std::string toHex(const unsigned char* data, unsigned int len) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (unsigned int i = 0; i < len; ++i) {
    out << std::setw(2) << static_cast<int>(data[i]);
  }
  return out.str();
}

std::vector<unsigned char> fromHex(const std::string& hex) {
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
}

CryptoEngine::CryptoEngine() : sodiumReady_(sodium_init() >= 0) {
  if (!sodiumReady_) {
    throw std::runtime_error("libsodium initialization failed");
  }
}

CryptoEngine::~CryptoEngine() = default;

std::string CryptoEngine::hashPassword(const std::string& password) const {
  std::vector<char> out(crypto_pwhash_STRBYTES);

  // Argon2id via libsodium gives memory-hard password hashing with secure defaults.
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

bool CryptoEngine::verifyPassword(const std::string& password, const std::string& hash) const {
  return crypto_pwhash_str_verify(hash.c_str(), password.c_str(), password.size()) == 0;
}

std::string CryptoEngine::computeHmacSha256(const std::string& key, const std::string& data) const {
  unsigned char mac[EVP_MAX_MD_SIZE] = {0};
  unsigned int macLen = 0;

  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
           reinterpret_cast<const unsigned char*>(data.data()), data.size(), mac, &macLen) == nullptr) {
    throw std::runtime_error("hmac generation failed");
  }

  return toHex(mac, macLen);
}

bool CryptoEngine::verifyHmacSha256(const std::string& key, const std::string& data, const std::string& expectedHexMac) const {
  const std::string computedHex = computeHmacSha256(key, data);
  const auto expected = fromHex(expectedHexMac);
  const auto computed = fromHex(computedHex);

  if (expected.size() != computed.size()) {
    return false;
  }

  // OpenSSL constant-time comparison prevents timing leakage on MAC checks.
  return CRYPTO_memcmp(expected.data(), computed.data(), expected.size()) == 0;
}
