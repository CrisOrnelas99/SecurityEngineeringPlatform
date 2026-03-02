#include "file_crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {
std::vector<unsigned char> readBytes(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw std::runtime_error("unable to open input file");
  }
  return std::vector<unsigned char>(std::istreambuf_iterator<char>(in), {});
}

void writeBytes(const std::string& path, const std::vector<unsigned char>& data) {
  std::ofstream out(path, std::ios::binary);
  if (!out) {
    throw std::runtime_error("unable to open output file");
  }
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

std::vector<unsigned char> fromHex(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    throw std::runtime_error("invalid key hex");
  }

  std::vector<unsigned char> out(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    out[i / 2] = static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16));
  }
  return out;
}

std::string toHex(const unsigned char* data, size_t len) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    out << std::setw(2) << static_cast<int>(data[i]);
  }
  return out.str();
}
}

nlohmann::json FileCrypto::encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& keyHex) const {
  auto plaintext = readBytes(inputPath);
  auto key = fromHex(keyHex);
  if (key.size() != 32) {
    throw std::runtime_error("AES-256-GCM key must be 32 bytes");
  }

  std::vector<unsigned char> iv(12, 0);
  if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
    throw std::runtime_error("iv generation failed");
  }

  std::vector<unsigned char> ciphertext(plaintext.size() + 16);
  std::vector<unsigned char> tag(16, 0);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("cipher context failed");
  }

  int len = 0;
  int total = 0;

  try {
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
      throw std::runtime_error("encrypt initialization failed");
    }

    total = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len) != 1) {
      throw std::runtime_error("encrypt finalization failed");
    }

    total += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
      throw std::runtime_error("tag retrieval failed");
    }

    EVP_CIPHER_CTX_free(ctx);
  } catch (...) {
    EVP_CIPHER_CTX_free(ctx);
    throw;
  }

  ciphertext.resize(static_cast<size_t>(total));

  std::vector<unsigned char> out;
  out.insert(out.end(), iv.begin(), iv.end());
  out.insert(out.end(), tag.begin(), tag.end());
  out.insert(out.end(), ciphertext.begin(), ciphertext.end());
  writeBytes(outputPath, out);

  return {{"success", true}, {"iv", toHex(iv.data(), iv.size())}, {"tag", toHex(tag.data(), tag.size())}};
}

nlohmann::json FileCrypto::decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& keyHex) const {
  auto blob = readBytes(inputPath);
  auto key = fromHex(keyHex);
  if (key.size() != 32) {
    throw std::runtime_error("AES-256-GCM key must be 32 bytes");
  }
  if (blob.size() < 28) {
    throw std::runtime_error("encrypted blob is too small");
  }

  std::vector<unsigned char> iv(blob.begin(), blob.begin() + 12);
  std::vector<unsigned char> tag(blob.begin() + 12, blob.begin() + 28);
  std::vector<unsigned char> ciphertext(blob.begin() + 28, blob.end());
  std::vector<unsigned char> plaintext(ciphertext.size() + 16);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("cipher context failed");
  }

  int len = 0;
  int total = 0;

  try {
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
      throw std::runtime_error("decrypt initialization failed");
    }

    total = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
      throw std::runtime_error("tag setup failed");
    }

    const int finalStatus = EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len);
    if (finalStatus != 1) {
      throw std::runtime_error("authentication tag mismatch");
    }

    total += len;
    EVP_CIPHER_CTX_free(ctx);
  } catch (...) {
    EVP_CIPHER_CTX_free(ctx);
    throw;
  }

  plaintext.resize(static_cast<size_t>(total));
  writeBytes(outputPath, plaintext);
  return {{"success", true}};
}
