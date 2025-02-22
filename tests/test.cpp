#define CATCH_CONFIG_MAIN  // This defines the entry point for Catch2
#include <catch2/catch.hpp>  // Include the Catch2 header

#include "encryptor.h"
#include "decryptor.h"
#include "keymanager.h"
#include "logger.h"

#define AES_BLOCK_SIZE 32

// Basic Encryption and Decryption Test
TEST_CASE("Basic Encryption and Decryption Test", "[encryptor][decryptor]") {
	std::string key = KeyManager::generateKey();
	std::string plaintext = "Hello, World!";
	
	std::string encrypted = Encryptor::encrypt(plaintext, key);
	std::string decrypted = Decryptor::decrypt(encrypted, key);

	REQUIRE(plaintext == decrypted);  // Catch2 equivalent of 'assert'
}

// Key Generation Test
TEST_CASE("Key Generation Test", "[keymanager]") {
	std::string key1 = KeyManager::generateKey();
	std::string key2 = KeyManager::generateKey();

	REQUIRE(key1.size() == AES_BLOCK_SIZE);
	REQUIRE(key2.size() == AES_BLOCK_SIZE);
	REQUIRE(key1 != key2);  // The keys should be different
}

// Edge Case Test for Empty String
TEST_CASE("Empty String Encryption and Decryption Test", "[encryptor][decryptor]") {
	std::string key = KeyManager::generateKey();
	std::string encrypted = Encryptor::encrypt("", key);
	std::string decrypted = Decryptor::decrypt(encrypted, key);

	REQUIRE(decrypted == "");
}

// Edge Case Test for Very Large Input
TEST_CASE("Large Input Encryption and Decryption Test", "[encryptor][decryptor]") {
	std::string key = KeyManager::generateKey();
	std::string plaintext(10 * 1024 * 1024, 'A'); // 10MB of 'A' characters
	std::string encrypted = Encryptor::encrypt(plaintext, key);
	std::string decrypted = Decryptor::decrypt(encrypted, key);

	REQUIRE(plaintext == decrypted);
}

// Test for Invalid Key Length
TEST_CASE("Invalid Key Length Test", "[encryptor]") {
	std::string invalidKey = "shortkey"; // Invalid key length (not 32 bytes)
	std::string plaintext = "Some text";
	
	// This should throw an exception
	REQUIRE_THROWS_AS(Encryptor::encrypt(plaintext, invalidKey), std::invalid_argument);
}
