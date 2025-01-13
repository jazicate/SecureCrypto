<<<<<<< HEAD
#ifndef DECRYPTOR_H
#define DECRYPTOR_H

#include <string>

extern int AES_BLOCK_SIZE;

class Decryptor {
public:
	static std::string decrypt(const std::string &ciphertext, const std::string &key);
};

#endif
=======
#pragma once
#include <string>

class Decryptor {
public:
	static std::string decrypt(const std::string &ciphertext, const std::string &key);
};
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21
