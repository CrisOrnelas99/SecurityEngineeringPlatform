#include "token_service.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <ctime>
#include <stdexcept>
#include <vector>

namespace {
std::string base64UrlEncode(const std::string& input) {
  if (input.empty()) {
    return "";
  }

  std::string out;
  out.resize(4 * ((input.size() + 2) / 3));
  const int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                                  reinterpret_cast<const unsigned char*>(input.data()),
                                  static_cast<int>(input.size()));
  out.resize(static_cast<size_t>(len));

  for (char& c : out) {
    if (c == '+') c = '-';
    if (c == '/') c = '_';
  }

  while (!out.empty() && out.back() == '=') {
    out.pop_back();
  }

  return out;
}

std::string base64UrlDecode(const std::string& input) {
  std::string working = input;
  for (char& c : working) {
    if (c == '-') c = '+';
    if (c == '_') c = '/';
  }

  while (working.size() % 4 != 0) {
    working.push_back('=');
  }

  std::string out;
  out.resize((working.size() * 3) / 4);
  const int len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                                  reinterpret_cast<const unsigned char*>(working.data()),
                                  static_cast<int>(working.size()));
  if (len < 0) {
    throw std::runtime_error("base64 decode failed");
  }

  out.resize(static_cast<size_t>(len));
  return out;
}

std::string signSha256(const std::string& secret, const std::string& data) {
  unsigned char mac[EVP_MAX_MD_SIZE] = {0};
  unsigned int macLen = 0;

  if (HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
           reinterpret_cast<const unsigned char*>(data.data()), data.size(), mac, &macLen) == nullptr) {
    throw std::runtime_error("jwt signature failed");
  }

  return std::string(reinterpret_cast<char*>(mac), macLen);
}
}

nlohmann::json TokenService::signJwtHS256(const nlohmann::json& claims, const std::string& secret, long expiresInSeconds) const {
  nlohmann::json header = { {"alg", "HS256"}, {"typ", "JWT"} };
  nlohmann::json payload = claims;
  payload["iat"] = std::time(nullptr);
  payload["exp"] = std::time(nullptr) + expiresInSeconds;

  const std::string encodedHeader = base64UrlEncode(header.dump());
  const std::string encodedPayload = base64UrlEncode(payload.dump());
  const std::string signingInput = encodedHeader + "." + encodedPayload;
  const std::string signature = base64UrlEncode(signSha256(secret, signingInput));

  return {
    {"success", true},
    {"token", signingInput + "." + signature},
    {"exp", payload["exp"]}
  };
}

nlohmann::json TokenService::verifyJwtHS256(const std::string& token, const std::string& secret) const {
  const auto firstDot = token.find('.');
  const auto secondDot = token.rfind('.');
  if (firstDot == std::string::npos || secondDot == std::string::npos || firstDot == secondDot) {
    return { {"valid", false}, {"error", "Malformed token"} };
  }

  const std::string encodedHeader = token.substr(0, firstDot);
  const std::string encodedPayload = token.substr(firstDot + 1, secondDot - firstDot - 1);
  const std::string encodedSignature = token.substr(secondDot + 1);

  const std::string signingInput = encodedHeader + "." + encodedPayload;
  const std::string expectedSignature = base64UrlEncode(signSha256(secret, signingInput));

  if (expectedSignature.size() != encodedSignature.size() ||
      CRYPTO_memcmp(expectedSignature.data(), encodedSignature.data(), expectedSignature.size()) != 0) {
    return { {"valid", false}, {"error", "Signature mismatch"} };
  }

  try {
    const auto payload = nlohmann::json::parse(base64UrlDecode(encodedPayload));
    const auto now = std::time(nullptr);
    if (payload.contains("exp") && payload["exp"].is_number_integer() && payload["exp"].get<long>() < now) {
      return { {"valid", false}, {"error", "Token expired"}, {"payload", payload} };
    }

    return { {"valid", true}, {"payload", payload} };
  } catch (const std::exception& ex) {
    return { {"valid", false}, {"error", ex.what()} };
  }
}
