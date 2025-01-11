#include <cassert>
#include <iostream>

#include "encryptor.h"
#include "decryptor.h"
#include "keymanager.h"
#include "logger.h"

#define AES_BLOCK_SIZE 16

// Basic Encryption and Decryption Test
void testBasicEncryptionDecryption() {
	std::string key = KeyManager::generateKey();
	std::string plaintext = "Hello, World!";
	std::string encrypted = Encryptor::encrypt(plaintext, key);
	std::string decrypted = Decryptor::decrypt(encrypted, key);
		
	assert(plaintext == decrypted);
	std::cout << "Basic Encryption and Decryption Test Passed!" << std::endl;
}

// Key Generation Test
void testKeyGeneration() {
	std::string key1 = KeyManager::generateKey();
	std::string key2 = KeyManager::generateKey();
		
	assert(key1.size() == AES_BLOCK_SIZE && key2.size() == AES_BLOCK_SIZE);
	assert(key1 != key2); // The keys should be different
	std::cout << "Key Generation Test Passed!" << std::endl;
}

// Edge Case Test for Empty String
void testEmptyStringEncryptionDecryption() {
	std::string key = KeyManager::generateKey();
	std::string encrypted = Encryptor::encrypt("", key);
	std::string decrypted = Decryptor::decrypt(encrypted, key);
		
	assert(decrypted == "");
	std::cout << "Empty String Encryption and Decryption Test Passed!" << std::endl;
}

int main() {
	testBasicEncryptionDecryption();
	testKeyGeneration();
	testEmptyStringEncryptionDecryption();

	return 0;
}