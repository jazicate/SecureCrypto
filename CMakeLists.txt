cmake_minimum_required(VERSION 3.10)
project(SecureCryptoProject)

# Ensure C++17 support
set(CMAKE_CXX_STANDARD 17)

# Specify output directory for the executable
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Include the header files
include_directories(include)

# Add the executable and link all source files
add_executable(SecureCryptoProject
	src/main.cpp
	src/encryptor.cpp
	src/decryptor.cpp
	src/keymanager.cpp
	src/logger.cpp
)

# Specify the C++ standard
target_compile_features(SecureCryptoProject PRIVATE cxx_std_17)

# Include directories
target_include_directories(SecureCryptoProject PRIVATE include)

# Link OpenSSL library
find_package(OpenSSL REQUIRED)
target_link_libraries(SecureCryptoProject PRIVATE OpenSSL::Crypto)

# Optional: Enable testing if you have tests
enable_testing()
add_executable(TestProject 
	tests/test.cpp 
	src/encryptor.cpp 
	src/decryptor.cpp 
	src/keymanager.cpp)
target_include_directories(TestProject PRIVATE include)
target_link_libraries(TestProject PRIVATE OpenSSL::Crypto)
add_test(NAME TestProject COMMAND TestProject)
