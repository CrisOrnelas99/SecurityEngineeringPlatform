#include "crypto_engine.h"
#include "file_crypto.h"
#include "token_service.h"
#include "utils.h"

#include <exception>
#include <string>

int main(int argc, char** argv) {
  if (argc < 2) {
    printJson({{"success", false}, {"error", "missing operation"}});
    return 1;
  }

  const std::string op = argv[1];

  try {
    const auto input = parseJsonInput(readAllStdin());
    CryptoEngine crypto;
    TokenService tokenService;
    FileCrypto fileCrypto;

    if (op == "hash-password") {
      const std::string password = input.value("password", "");
      if (password.empty()) {
        throw std::runtime_error("password is required");
      }
      printJson({{"success", true}, {"hash", crypto.hashPassword(password)}});
      return 0;
    }

    if (op == "verify-password") {
      const std::string password = input.value("password", "");
      const std::string hash = input.value("hash", "");
      if (password.empty() || hash.empty()) {
        throw std::runtime_error("password and hash are required");
      }
      printJson({{"success", true}, {"valid", crypto.verifyPassword(password, hash)}});
      return 0;
    }

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

    if (op == "verify-jwt") {
      const std::string token = input.value("token", "");
      const std::string secret = input.value("secret", "");
      if (token.empty() || secret.empty()) {
        throw std::runtime_error("token and secret are required");
      }
      printJson(tokenService.verifyJwtHS256(token, secret));
      return 0;
    }

    if (op == "encrypt-file") {
      const std::string inputPath = input.value("inputPath", "");
      const std::string outputPath = input.value("outputPath", "");
      const std::string keyHex = input.value("keyHex", "");
      printJson(fileCrypto.encryptFile(inputPath, outputPath, keyHex));
      return 0;
    }

    if (op == "decrypt-file") {
      const std::string inputPath = input.value("inputPath", "");
      const std::string outputPath = input.value("outputPath", "");
      const std::string keyHex = input.value("keyHex", "");
      printJson(fileCrypto.decryptFile(inputPath, outputPath, keyHex));
      return 0;
    }

    if (op == "hmac") {
      const std::string key = input.value("key", "");
      const std::string data = input.value("data", "");
      if (key.empty()) {
        throw std::runtime_error("key is required");
      }
      printJson({{"success", true}, {"hmac", crypto.computeHmacSha256(key, data)}});
      return 0;
    }

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

    printJson({{"success", false}, {"error", "unknown operation"}});
    return 1;
  } catch (const std::exception& ex) {
    // Keep errors generic and structured so callers can reason without leaking secrets.
    printJson({{"success", false}, {"error", ex.what()}});
    return 1;
  }
}
