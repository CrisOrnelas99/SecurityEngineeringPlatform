#include <exception>
#include <string>
#include <nlohmann/json.hpp>
#include "crypto_engine.hpp"
#include "token_service.hpp"
#include "utils.hpp"

int main(int argc, char** argv) {
  // Require an operation argument (for example: hash-password, sign-jwt, hmac).
  if (argc < 2) {
    printJson({{"success", false}, {"error", "missing operation"}});
    return 1;
  }

  // Operation determines which crypto/token workflow this invocation runs.
  const std::string op = argv[1];

  try {
    // Read JSON from stdin and initialize helper services.
    const auto input = parseJsonInput(readAllStdin());
    CryptoEngine crypto;
    TokenService tokenService;

    // Create a password hash for secure storage.
    if (op == "hash-password") {
      const std::string password = input.value("password", "");
      if (password.empty()) {
        throw std::runtime_error("password is required");
      }
      printJson({{"success", true}, {"hash", crypto.hashPassword(password)}});
      return 0;
    }

    // Validate a plaintext password against an existing stored hash.
    if (op == "verify-password") {
      const std::string password = input.value("password", "");
      const std::string hash = input.value("hash", "");
      if (password.empty() || hash.empty()) {
        throw std::runtime_error("password and hash are required");
      }
      printJson({{"success", true}, {"valid", crypto.verifyPassword(password, hash)}});
      return 0;
    }

    // Sign a JWT with secret and optional expiration window.
    if (op == "sign-jwt") {
      const auto claims = input.value("claims", nlohmann::json::object());
      const std::string secret = input.value("secret", "");
      const long expiresIn = input.value("expiresIn", 900L);
      if (secret.empty()) {
        throw std::runtime_error("secret is required");
      }
      printJson(tokenService.signJwtHS256(claims, secret, expiresIn));
      return 0;
    }

    // Verify a JWT signature and claims validity with the provided secret.
    if (op == "verify-jwt") {
      const std::string token = input.value("token", "");
      const std::string secret = input.value("secret", "");
      if (token.empty() || secret.empty()) {
        throw std::runtime_error("token and secret are required");
      }
      printJson(tokenService.verifyJwtHS256(token, secret));
      return 0;
    }

    // Generate an HMAC-SHA256 tag for integrity/authenticity checks.
    if (op == "hmac") {
      const std::string key = input.value("key", "");
      const std::string data = input.value("data", "");
      if (key.empty()) {
        throw std::runtime_error("key is required");
      }
      printJson({{"success", true}, {"hmac", crypto.computeHmacSha256(key, data)}});
      return 0;
    }

    // Verify a provided HMAC matches recomputed value for this key+data.
    if (op == "verify-hmac") {
      const std::string key = input.value("key", "");
      const std::string data = input.value("data", "");
      const std::string expected = input.value("expected", "");
      if (key.empty() || expected.empty()) {
        throw std::runtime_error("key and expected are required");
      }
      printJson({{"success", true}, {"valid", crypto.verifyHmacSha256(key, data, expected)}});
      return 0;
    }

    // Reject unknown operations with a structured error payload.
    printJson({{"success", false}, {"error", "unknown operation"}});
    return 1;
  } catch (const std::exception& ex) {
    // Keep errors generic and structured so callers can reason without leaking secrets.
    printJson({{"success", false}, {"error", ex.what()}});
    return 1;
  }
}
