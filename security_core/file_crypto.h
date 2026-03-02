#pragma once

#include <nlohmann/json.hpp>

class FileCrypto {
public:
  nlohmann::json encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& keyHex) const;
  nlohmann::json decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& keyHex) const;
};
