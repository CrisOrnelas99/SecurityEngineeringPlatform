#pragma once

#include <string>
#include <nlohmann/json.hpp>

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
