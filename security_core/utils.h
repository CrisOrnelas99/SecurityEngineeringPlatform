#pragma once

#include <string>
#include <nlohmann/json.hpp>

std::string readAllStdin();
nlohmann::json parseJsonInput(const std::string& raw);
void printJson(const nlohmann::json& j);
