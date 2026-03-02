cmake_minimum_required(VERSION 3.16)
project(security_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(nlohmann_json REQUIRED)

add_executable(security_core
  main.cpp
  crypto_engine.cpp
  token_service.cpp
  file_crypto.cpp
  utils.cpp
)

target_include_directories(security_core PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(security_core PRIVATE OpenSSL::Crypto ${SODIUM_LIBRARIES} nlohmann_json::nlohmann_json)

if(MSVC)
  target_compile_options(security_core PRIVATE /W4)
else()
  target_compile_options(security_core PRIVATE -Wall -Wextra -Wpedantic)
endif()
