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

<<<<<<< HEAD

# Optional: Enable testing if you have tests
enable_testing()
# Add Catch2 as a dependency using FetchContent (this is a modern and convenient way)
include(FetchContent)
# Fetch Catch2 from GitHub
FetchContent_Declare(
	Catch2
	GIT_REPOSITORY https://github.com/catchorg/Catch2.git
	GIT_TAG v2.13.9  # Or the latest stable version
)
# Make Catch2 available in the project
FetchContent_MakeAvailable(Catch2)
# Add the TestProject executable for Catch2-based tests
add_executable(TestProject
	tests/test.cpp
	src/encryptor.cpp
	src/decryptor.cpp
	src/keymanager.cpp
	src/logger.cpp
)
# Include directories for the TestProject
target_include_directories(TestProject PRIVATE include)
# Link OpenSSL and Catch2 libraries for the test project
target_link_libraries(TestProject PRIVATE OpenSSL::Crypto Catch2::Catch2)
# Add a test to be run with CTest (optional)
=======
# Optional: Enable testing if you have tests
enable_testing()
add_executable(TestProject 
	tests/test.cpp 
	src/encryptor.cpp 
	src/decryptor.cpp 
	src/keymanager.cpp)
target_include_directories(TestProject PRIVATE include)
target_link_libraries(TestProject PRIVATE OpenSSL::Crypto)
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21
add_test(NAME TestProject COMMAND TestProject)
