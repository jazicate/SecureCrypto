#include <catch2/catch_test_macros.hpp>

#include "secure_crypto.h"

#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

void writeTextFile(const fs::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << content;
}

std::string readTextFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

void writeBinaryFile(const fs::path& path, const std::vector<unsigned char>& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(content.data()), static_cast<std::streamsize>(content.size()));
}

std::vector<unsigned char> makeLargeSample(size_t size) {
    std::vector<unsigned char> data(size);
    // Fixed seed keeps the test deterministic while still producing non-trivial binary data.
    std::mt19937 generator(42);
    std::uniform_int_distribution<int> distribution(0, 255);
    for (unsigned char& byte : data) {
        byte = static_cast<unsigned char>(distribution(generator));
    }
    return data;
}

}  // namespace

TEST_CASE("single file round trip and metadata", "[file][metadata]") {
    // A unique directory keeps the test reliable even if multiple runs happen close together.
    const fs::path tempDir = fs::temp_directory_path() / ("securecrypto_tests_" + std::to_string(getpid()) + "_single");
    fs::create_directories(tempDir);

    const fs::path plaintextPath = tempDir / "plain.txt";
    const fs::path encryptedPath = tempDir / "plain.enc";
    const fs::path decryptedPath = tempDir / "plain.dec";
    const std::string password = "correct-horse-battery-staple";
    const std::string content = "Confidential launch checklist\nline2\nline3";

    writeTextFile(plaintextPath, content);
    securecrypto::encryptFile(plaintextPath.string(), encryptedPath.string(), password);
    securecrypto::decryptFile(encryptedPath.string(), decryptedPath.string(), password);

    // The decrypted file should match the original exactly.
    REQUIRE(readTextFile(decryptedPath) == content);

    // Inspect lets us check the header without needing to decrypt again.
    const auto metadata = securecrypto::inspectFile(encryptedPath.string());
    REQUIRE(metadata.version == 1);
    REQUIRE(metadata.salt.size() == 16);
    REQUIRE(metadata.nonce.size() == 12);
    REQUIRE(metadata.tag.size() == 16);
    REQUIRE(metadata.plaintextSize == content.size());

    REQUIRE_THROWS(securecrypto::decryptFile(encryptedPath.string(), decryptedPath.string(), "wrong-password"));

    auto ciphertext = securecrypto::readFile(encryptedPath.string());
    REQUIRE_FALSE(ciphertext.empty());
    // Flipping one byte should make GCM authentication fail during decryption.
    ciphertext.back() ^= 0x01;
    const fs::path tamperedPath = tempDir / "tampered.enc";
    securecrypto::writeFile(tamperedPath.string(), ciphertext);

    REQUIRE_THROWS(securecrypto::decryptFile(tamperedPath.string(), decryptedPath.string(), password));

    fs::remove_all(tempDir);
}

TEST_CASE("streaming handles large and empty files", "[streaming][file]") {
    const fs::path tempDir = fs::temp_directory_path() / ("securecrypto_tests_" + std::to_string(getpid()) + "_streaming");
    fs::create_directories(tempDir);

    const fs::path largePath = tempDir / "large.bin";
    const fs::path largeEncryptedPath = tempDir / "large.enc";
    const fs::path largeDecryptedPath = tempDir / "large.dec";
    const fs::path emptyPath = tempDir / "empty.txt";
    const fs::path emptyEncryptedPath = tempDir / "empty.enc";
    const fs::path emptyDecryptedPath = tempDir / "empty.dec";
    const std::string password = "correct-horse-battery-staple";

    // A multi-megabyte sample forces the chunked I/O path rather than the trivial small-file path.
    const std::vector<unsigned char> largeSample = makeLargeSample(3 * 1024 * 1024);
    writeBinaryFile(largePath, largeSample);
    securecrypto::encryptFile(largePath.string(), largeEncryptedPath.string(), password);
    securecrypto::decryptFile(largeEncryptedPath.string(), largeDecryptedPath.string(), password);
    REQUIRE(securecrypto::readFile(largeDecryptedPath.string()) == largeSample);

    writeTextFile(emptyPath, "");
    securecrypto::encryptFile(emptyPath.string(), emptyEncryptedPath.string(), password);
    securecrypto::decryptFile(emptyEncryptedPath.string(), emptyDecryptedPath.string(), password);
    REQUIRE(readTextFile(emptyDecryptedPath).empty());

    fs::remove_all(tempDir);
}

TEST_CASE("directory recursion preserves structure and names", "[directory][recursion]") {
    const fs::path tempDir = fs::temp_directory_path() / ("securecrypto_tests_" + std::to_string(getpid()) + "_dirs");
    fs::create_directories(tempDir);

    const fs::path inputDir = tempDir / "input_dir";
    const fs::path nestedDir = inputDir / "nested";
    const fs::path encryptedDir = tempDir / "encrypted_dir";
    const fs::path decryptedDir = tempDir / "decrypted_dir";
    const fs::path oddNameEncryptedDir = tempDir / "odd_names_encrypted";
    const fs::path oddNameDecryptedDir = tempDir / "odd_names_decrypted";
    const std::string password = "correct-horse-battery-staple";

    fs::create_directories(nestedDir);
    writeTextFile(inputDir / "root.txt", "root file");
    writeTextFile(nestedDir / "child.txt", "nested file");
    writeTextFile(nestedDir / "notes", "no extension file");

    const auto encryptStats = securecrypto::encryptPath(inputDir.string(), encryptedDir.string(), password);
    // The stats are part of the public behavior used by the CLI logs.
    REQUIRE(encryptStats.filesProcessed == 3);
    REQUIRE(encryptStats.directoriesProcessed == 2);

    const auto decryptStats = securecrypto::decryptPath(encryptedDir.string(), decryptedDir.string(), password);
    REQUIRE(decryptStats.filesProcessed == 3);
    REQUIRE(decryptStats.directoriesProcessed == 2);
    REQUIRE(readTextFile(decryptedDir / "root.txt") == "root file");
    REQUIRE(readTextFile(decryptedDir / "nested" / "child.txt") == "nested file");
    REQUIRE(readTextFile(decryptedDir / "nested" / "notes") == "no extension file");

    fs::create_directories(oddNameEncryptedDir / "nested");
    writeTextFile(oddNameEncryptedDir / "report.data", "odd file name");
    writeTextFile(oddNameEncryptedDir / "nested" / "archive.bin", "nested odd file");
    const auto oddEncryptStats = securecrypto::encryptPath(oddNameEncryptedDir.string(),
                                                           oddNameEncryptedDir.string() + "_out",
                                                           password);
    REQUIRE(oddEncryptStats.filesProcessed == 2);

    const auto oddDecryptStats = securecrypto::decryptPath((oddNameEncryptedDir.string() + "_out"),
                                                           oddNameDecryptedDir.string(),
                                                           password);
    REQUIRE(oddDecryptStats.filesProcessed == 2);
    REQUIRE(readTextFile(oddNameDecryptedDir / "report.data") == "odd file name");
    REQUIRE(readTextFile(oddNameDecryptedDir / "nested" / "archive.bin") == "nested odd file");

    fs::remove_all(tempDir);
}

TEST_CASE("invalid inputs are rejected", "[errors][validation]") {
    const fs::path tempDir = fs::temp_directory_path() / ("securecrypto_tests_" + std::to_string(getpid()) + "_errors");
    fs::create_directories(tempDir);

    const fs::path plaintextPath = tempDir / "plain.txt";
    const fs::path invalidEnvelopePath = tempDir / "invalid.enc";
    const std::string password = "correct-horse-battery-staple";

    writeTextFile(plaintextPath, "hello");
    writeTextFile(invalidEnvelopePath, "not a real encrypted file");

    REQUIRE_THROWS(securecrypto::inspectFile(invalidEnvelopePath.string()));
    REQUIRE_THROWS(securecrypto::decryptFile(invalidEnvelopePath.string(),
                                            (tempDir / "invalid.dec").string(),
                                            password));
    REQUIRE_THROWS(securecrypto::encryptFile(plaintextPath.string(),
                                            (tempDir / "should_not_exist.enc").string(),
                                            ""));
    REQUIRE_THROWS(securecrypto::encryptPath((tempDir / "missing_dir").string(),
                                            (tempDir / "missing_out").string(),
                                            password));

    fs::remove_all(tempDir);
}
