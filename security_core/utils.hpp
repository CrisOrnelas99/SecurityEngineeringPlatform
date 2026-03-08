#pragma once

#include <iostream>
#include <sstream>
#include <string>
#include <nlohmann/json.hpp>

// Read full stdin stream so CLI operations can accept JSON request bodies.
inline std::string readAllStdin() {
  std::ostringstream buffer;
  buffer << std::cin.rdbuf();
  return buffer.str();
}

// Parse JSON input; when no stdin body is provided, return empty object.
inline nlohmann::json parseJsonInput(const std::string& raw) {
  if (raw.empty()) {
    return nlohmann::json::object();
  }
  return nlohmann::json::parse(raw);
}

// Emit one JSON response line for consistent machine-readable CLI output.
inline void printJson(const nlohmann::json& j) {
  std::cout << j.dump() << std::endl;
}
