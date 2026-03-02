#pragma once

#include <nlohmann/json.hpp>

class TokenService {
public:
  nlohmann::json signJwtHS256(const nlohmann::json& claims, const std::string& secret, long expiresInSeconds) const;
  nlohmann::json verifyJwtHS256(const std::string& token, const std::string& secret) const;
};
