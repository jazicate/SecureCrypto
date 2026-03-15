cmake_minimum_required(VERSION 3.20)
project(SecureCrypto VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

find_package(OpenSSL REQUIRED)
find_package(Catch2 3 REQUIRED)

add_library(securecrypto_lib
    src/secure_crypto.cpp
    src/cli.cpp
    src/logger.cpp
)

target_include_directories(securecrypto_lib PUBLIC include)
target_link_libraries(securecrypto_lib PUBLIC OpenSSL::Crypto)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(securecrypto_lib PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(securecrypto src/main.cpp)
target_link_libraries(securecrypto PRIVATE securecrypto_lib)

include(CTest)
include(Catch)

add_executable(securecrypto_tests tests/test_secure_crypto.cpp)
target_link_libraries(securecrypto_tests PRIVATE securecrypto_lib Catch2::Catch2WithMain)
catch_discover_tests(securecrypto_tests)
