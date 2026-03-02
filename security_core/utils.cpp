#include "utils.h"

#include <iostream>
#include <sstream>

std::string readAllStdin() {
  std::ostringstream buffer;
  buffer << std::cin.rdbuf();
  return buffer.str();
}

nlohmann::json parseJsonInput(const std::string& raw) {
  if (raw.empty()) {
    return nlohmann::json::object();
  }
  return nlohmann::json::parse(raw);
}

void printJson(const nlohmann::json& j) {
  std::cout << j.dump() << std::endl;
}
