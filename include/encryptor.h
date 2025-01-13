<<<<<<< HEAD
#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <string>

extern int AES_BLOCK_SIZE;

class Encryptor {
public:
	static std::string encrypt(const std::string &plaintext, const std::string &key);
};

#endif
=======
#pragma once
#include <string>

class Encryptor {
public:
	static std::string encrypt(const std::string &plaintext, const std::string &key);
};
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21
