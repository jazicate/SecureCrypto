#include "secure_crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace securecrypto {
namespace {

namespace fs = std::filesystem;

constexpr std::array<unsigned char, 8> kMagic = {'S', 'C', 'R', 'Y', 'P', 'T', '0', '1'};
constexpr uint8_t kVersion = 1;
constexpr size_t kKeyLength = 32;
constexpr size_t kSaltLength = 16;
constexpr size_t kNonceLength = 12;
constexpr size_t kTagLength = 16;
constexpr size_t kChunkSize = 64 * 1024;

struct ParsedEnvelope {
    FileMetadata metadata;
    size_t ciphertextOffset = 0;
};

void appendUint32(std::vector<unsigned char>& buffer, uint32_t value) {
    // The file format stores integers byte-by-byte so it is easy to parse later.
    for (size_t i = 0; i < 4; ++i) {
        buffer.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
    }
}

void appendUint64(std::vector<unsigned char>& buffer, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        buffer.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
    }
}

uint32_t readUint32(const std::vector<unsigned char>& buffer, size_t& offset) {
    if (offset + 4 > buffer.size()) {
        throw std::runtime_error("Unexpected end of encrypted file while reading uint32.");
    }

    uint32_t value = 0;
    for (size_t i = 0; i < 4; ++i) {
        value |= static_cast<uint32_t>(buffer[offset + i]) << (i * 8);
    }
    offset += 4;
    return value;
}

uint64_t readUint64(const std::vector<unsigned char>& buffer, size_t& offset) {
    if (offset + 8 > buffer.size()) {
        throw std::runtime_error("Unexpected end of encrypted file while reading uint64.");
    }

    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(buffer[offset + i]) << (i * 8);
    }
    offset += 8;
    return value;
}

std::vector<unsigned char> randomBytes(size_t length) {
    std::vector<unsigned char> bytes(length);
    // RAND_bytes asks OpenSSL for cryptographically secure randomness.
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("Failed to generate secure random bytes.");
    }
    return bytes;
}

std::vector<unsigned char> deriveKey(const std::string& password,
                                     const std::vector<unsigned char>& salt,
                                     const ScryptParams& params) {
    std::vector<unsigned char> key(kKeyLength);
    // The password itself is not used as the AES key; scrypt stretches it first.
    if (EVP_PBE_scrypt(password.c_str(),
                       password.size(),
                       salt.data(),
                       salt.size(),
                       params.n,
                       params.r,
                       params.p,
                       params.maxMemoryBytes,
                       key.data(),
                       key.size()) != 1) {
        throw std::runtime_error("Failed to derive key with scrypt.");
    }
    return key;
}

class CipherContext {
public:
    CipherContext() : ctx_(EVP_CIPHER_CTX_new()) {
        if (!ctx_) {
            throw std::runtime_error("Failed to allocate cipher context.");
        }
    }

    ~CipherContext() {
        EVP_CIPHER_CTX_free(ctx_);
    }

    EVP_CIPHER_CTX* get() const {
        return ctx_;
    }

private:
    EVP_CIPHER_CTX* ctx_;
};

size_t serializedHeaderSize() {
    // The header has a fixed size because the salt/nonce/tag lengths are fixed in this project.
    return kMagic.size() + 1 + 3 + 8 + 8 + 8 + 8 + 4 + 4 + kSaltLength + kNonceLength + kTagLength;
}

std::vector<unsigned char> serializeHeader(const FileMetadata& metadata) {
    // This writes the metadata in the exact order decryption expects to read it back.
    std::vector<unsigned char> envelope;
    envelope.reserve(serializedHeaderSize());

    envelope.insert(envelope.end(), kMagic.begin(), kMagic.end());
    envelope.push_back(metadata.version);
    envelope.push_back(static_cast<unsigned char>(metadata.salt.size()));
    envelope.push_back(static_cast<unsigned char>(metadata.nonce.size()));
    envelope.push_back(static_cast<unsigned char>(metadata.tag.size()));
    appendUint64(envelope, metadata.plaintextSize);
    appendUint64(envelope, metadata.ciphertextSize);
    appendUint64(envelope, metadata.scrypt.n);
    appendUint64(envelope, metadata.scrypt.maxMemoryBytes);
    appendUint32(envelope, metadata.scrypt.r);
    appendUint32(envelope, metadata.scrypt.p);
    envelope.insert(envelope.end(), metadata.salt.begin(), metadata.salt.end());
    envelope.insert(envelope.end(), metadata.nonce.begin(), metadata.nonce.end());
    envelope.insert(envelope.end(), metadata.tag.begin(), metadata.tag.end());
    return envelope;
}

ParsedEnvelope parseEnvelopeHeader(const std::vector<unsigned char>& envelope) {
    // Parsing is split from decryption so the inspect command can reuse the same logic.
    if (envelope.size() < kMagic.size() + 1 + 3 + 8 + 8 + 8 + 8 + 4 + 4) {
        throw std::runtime_error("Encrypted file is too small to be valid.");
    }

    size_t offset = 0;
    for (unsigned char expected : kMagic) {
        if (envelope[offset++] != expected) {
            throw std::runtime_error("Invalid file magic. This is not a securecrypto artifact.");
        }
    }

    ParsedEnvelope parsed;
    parsed.metadata.version = envelope[offset++];
    if (parsed.metadata.version != kVersion) {
        throw std::runtime_error("Unsupported encrypted file version.");
    }

    const size_t saltLength = envelope[offset++];
    const size_t nonceLength = envelope[offset++];
    const size_t tagLength = envelope[offset++];
    parsed.metadata.plaintextSize = readUint64(envelope, offset);
    parsed.metadata.ciphertextSize = readUint64(envelope, offset);
    parsed.metadata.scrypt.n = readUint64(envelope, offset);
    parsed.metadata.scrypt.maxMemoryBytes = readUint64(envelope, offset);
    parsed.metadata.scrypt.r = readUint32(envelope, offset);
    parsed.metadata.scrypt.p = readUint32(envelope, offset);

    const size_t headerRemainder = saltLength + nonceLength + tagLength;
    if (offset + headerRemainder > envelope.size()) {
        throw std::runtime_error("Encrypted file header is truncated.");
    }

    parsed.metadata.salt.assign(envelope.begin() + static_cast<std::ptrdiff_t>(offset),
                                envelope.begin() + static_cast<std::ptrdiff_t>(offset + saltLength));
    offset += saltLength;
    parsed.metadata.nonce.assign(envelope.begin() + static_cast<std::ptrdiff_t>(offset),
                                 envelope.begin() + static_cast<std::ptrdiff_t>(offset + nonceLength));
    offset += nonceLength;
    parsed.metadata.tag.assign(envelope.begin() + static_cast<std::ptrdiff_t>(offset),
                               envelope.begin() + static_cast<std::ptrdiff_t>(offset + tagLength));
    offset += tagLength;
    parsed.ciphertextOffset = offset;
    return parsed;
}

void ensureParentDirectoryExists(const fs::path& path) {
    const fs::path parent = path.parent_path();
    if (!parent.empty()) {
        // Recursive mode may need to build nested output directories on the fly.
        fs::create_directories(parent);
    }
}

std::string stripEncSuffix(const fs::path& path) {
    const std::string name = path.filename().string();
    if (name.size() > 4 && name.substr(name.size() - 4) == ".enc") {
        return name.substr(0, name.size() - 4);
    }
    return name + ".dec";
}

fs::path defaultEncryptedPath(const fs::path& inputRoot, const fs::path& outputRoot, const fs::path& current) {
    if (fs::is_regular_file(inputRoot)) {
        return outputRoot;
    }

    const fs::path relative = fs::relative(current, inputRoot);
    return outputRoot / relative.string().append(".enc");
}

fs::path defaultDecryptedPath(const fs::path& inputRoot, const fs::path& outputRoot, const fs::path& current) {
    if (fs::is_regular_file(inputRoot)) {
        return outputRoot;
    }

    const fs::path relative = fs::relative(current, inputRoot);
    const fs::path parent = relative.parent_path();
    return outputRoot / parent / stripEncSuffix(relative);
}

FileMetadata createMetadataForEncryption(uint64_t plaintextSize) {
    FileMetadata metadata;
    // Each encrypted file gets its own salt and nonce so keys/keystreams are not reused.
    metadata.version = kVersion;
    metadata.plaintextSize = plaintextSize;
    metadata.ciphertextSize = plaintextSize;
    metadata.salt = randomBytes(kSaltLength);
    metadata.nonce = randomBytes(kNonceLength);
    metadata.tag.assign(kTagLength, 0);
    return metadata;
}

void encryptStream(std::istream& input, std::ostream& output, FileMetadata& metadata, const std::string& password) {
    const auto key = deriveKey(password, metadata.salt, metadata.scrypt);
    CipherContext ctx;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(metadata.nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), metadata.nonce.data()) != 1) {
        throw std::runtime_error("Failed to initialize AES-256-GCM encryption.");
    }

    std::vector<unsigned char> inBuffer(kChunkSize);
    std::vector<unsigned char> outBuffer(kChunkSize + kTagLength);
    // The loop processes one chunk at a time so large files do not live entirely in RAM.
    while (input) {
        input.read(reinterpret_cast<char*>(inBuffer.data()), static_cast<std::streamsize>(inBuffer.size()));
        const std::streamsize bytesRead = input.gcount();
        if (bytesRead <= 0) {
            break;
        }

        int bytesWritten = 0;
        if (EVP_EncryptUpdate(ctx.get(),
                              outBuffer.data(),
                              &bytesWritten,
                              inBuffer.data(),
                              static_cast<int>(bytesRead)) != 1) {
            throw std::runtime_error("Encryption failed while processing a chunk.");
        }

        output.write(reinterpret_cast<const char*>(outBuffer.data()), bytesWritten);
    }

    int finalBytes = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), outBuffer.data(), &finalBytes) != 1) {
        throw std::runtime_error("Encryption finalization failed.");
    }

    output.write(reinterpret_cast<const char*>(outBuffer.data()), finalBytes);

    if (!output) {
        throw std::runtime_error("Failed while writing encrypted output.");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(metadata.tag.size()), metadata.tag.data()) != 1) {
        throw std::runtime_error("Failed to retrieve the authentication tag.");
    }
}

void decryptStream(std::istream& input,
                   std::ostream& output,
                   const FileMetadata& metadata,
                   const std::string& password,
                   size_t ciphertextOffset) {
    const auto key = deriveKey(password, metadata.salt, metadata.scrypt);
    CipherContext ctx;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(metadata.nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), metadata.nonce.data()) != 1) {
        throw std::runtime_error("Failed to initialize AES-256-GCM decryption.");
    }

    input.seekg(static_cast<std::streamoff>(ciphertextOffset), std::ios::beg);
    std::vector<unsigned char> inBuffer(kChunkSize);
    std::vector<unsigned char> outBuffer(kChunkSize + kTagLength);
    // We trust the header enough to know how many ciphertext bytes should follow.
    uint64_t remaining = metadata.ciphertextSize;

    while (remaining > 0) {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, inBuffer.size()));
        input.read(reinterpret_cast<char*>(inBuffer.data()), static_cast<std::streamsize>(chunk));
        if (input.gcount() != static_cast<std::streamsize>(chunk)) {
            throw std::runtime_error("Encrypted file ended before all ciphertext bytes were read.");
        }

        int bytesWritten = 0;
        if (EVP_DecryptUpdate(ctx.get(),
                              outBuffer.data(),
                              &bytesWritten,
                              inBuffer.data(),
                              static_cast<int>(chunk)) != 1) {
            throw std::runtime_error("Decryption failed while processing a chunk.");
        }

        output.write(reinterpret_cast<const char*>(outBuffer.data()), bytesWritten);
        remaining -= chunk;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(),
                            EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(metadata.tag.size()),
                            const_cast<unsigned char*>(metadata.tag.data())) != 1) {
        throw std::runtime_error("Failed to attach the authentication tag for verification.");
    }

    int finalBytes = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), outBuffer.data(), &finalBytes) != 1) {
        throw std::runtime_error("Authentication failed. Password or ciphertext is invalid.");
    }

    output.write(reinterpret_cast<const char*>(outBuffer.data()), finalBytes);
    if (!output) {
        throw std::runtime_error("Failed while writing decrypted output.");
    }
}

void encryptSingleFile(const fs::path& inputPath, const fs::path& outputPath, const std::string& password) {
    std::ifstream input(inputPath, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to open input file: " + inputPath.string());
    }

    ensureParentDirectoryExists(outputPath);
    std::fstream output(outputPath, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("Unable to open output file: " + outputPath.string());
    }

    // We write a placeholder header first, stream the ciphertext, then seek back to fill in the final tag.
    FileMetadata metadata = createMetadataForEncryption(fs::file_size(inputPath));
    const std::vector<unsigned char> placeholderHeader = serializeHeader(metadata);
    output.write(reinterpret_cast<const char*>(placeholderHeader.data()),
                 static_cast<std::streamsize>(placeholderHeader.size()));

    encryptStream(input, output, metadata, password);

    output.seekp(0, std::ios::beg);
    const std::vector<unsigned char> finalHeader = serializeHeader(metadata);
    output.write(reinterpret_cast<const char*>(finalHeader.data()),
                 static_cast<std::streamsize>(finalHeader.size()));
}

void decryptSingleFile(const fs::path& inputPath, const fs::path& outputPath, const std::string& password) {
    std::ifstream input(inputPath, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to open input file: " + inputPath.string());
    }

    std::vector<unsigned char> header(serializedHeaderSize());
    // Only the header is needed up front; the ciphertext stays on disk and is streamed later.
    input.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    header.resize(static_cast<size_t>(input.gcount()));
    ParsedEnvelope parsed = parseEnvelopeHeader(header);

    ensureParentDirectoryExists(outputPath);
    const fs::path tempPath = outputPath.string() + ".tmp";
    std::ofstream tempOutput(tempPath, std::ios::binary | std::ios::trunc);
    if (!tempOutput) {
        throw std::runtime_error("Unable to open temporary file: " + tempPath.string());
    }

    try {
        // Decryption writes to a temporary file so a failed auth check never leaves a fake plaintext behind.
        decryptStream(input, tempOutput, parsed.metadata, password, parsed.ciphertextOffset);
        tempOutput.close();

        if (fs::exists(outputPath)) {
            fs::remove(outputPath);
        }
        fs::rename(tempPath, outputPath);
    } catch (...) {
        tempOutput.close();
        fs::remove(tempPath);
        throw;
    }
}

PathStats processDirectory(const fs::path& inputRoot,
                           const fs::path& outputRoot,
                           const std::string& password,
                           bool encryptMode) {
    PathStats stats;
    fs::create_directories(outputRoot);
    ++stats.directoriesProcessed;

    for (const fs::directory_entry& entry : fs::recursive_directory_iterator(inputRoot)) {
        if (entry.is_directory()) {
            ++stats.directoriesProcessed;
            continue;
        }

        if (!entry.is_regular_file()) {
            continue;
        }

        const fs::path source = entry.path();
        // Encryption adds ".enc"; decryption removes it when reconstructing file names.
        const fs::path destination = encryptMode
            ? defaultEncryptedPath(inputRoot, outputRoot, source)
            : defaultDecryptedPath(inputRoot, outputRoot, source);

        if (encryptMode) {
            encryptSingleFile(source, destination, password);
        } else {
            decryptSingleFile(source, destination, password);
        }
        ++stats.filesProcessed;
    }

    return stats;
}

}  // namespace

std::vector<unsigned char> readFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to open input file: " + path);
    }

    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    input.seekg(0, std::ios::beg);

    // This helper is meant for small files and tests, not the streaming encryption path.
    std::vector<unsigned char> data(static_cast<size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }

    if (!input && !input.eof()) {
        throw std::runtime_error("Failed to read input file: " + path);
    }

    return data;
}

void writeFile(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("Unable to open output file: " + path);
    }

    if (!data.empty()) {
        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }

    if (!output) {
        throw std::runtime_error("Failed to write output file: " + path);
    }
}

void encryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    if (password.empty()) {
        throw std::invalid_argument("Password must not be empty.");
    }
    // This is the single-file entry point used by both tests and the directory walker.
    encryptSingleFile(inputPath, outputPath, password);
}

void decryptFile(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    if (password.empty()) {
        throw std::invalid_argument("Password must not be empty.");
    }
    decryptSingleFile(inputPath, outputPath, password);
}

PathStats encryptPath(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    if (password.empty()) {
        throw std::invalid_argument("Password must not be empty.");
    }

    const fs::path source(inputPath);
    const fs::path destination(outputPath);
    if (fs::is_regular_file(source)) {
        // File mode returns a one-file summary so the CLI can print consistent output.
        encryptSingleFile(source, destination, password);
        return {1, 0};
    }
    if (fs::is_directory(source)) {
        return processDirectory(source, destination, password, true);
    }
    throw std::runtime_error("Input path is neither a regular file nor a directory: " + inputPath);
}

PathStats decryptPath(const std::string& inputPath, const std::string& outputPath, const std::string& password) {
    if (password.empty()) {
        throw std::invalid_argument("Password must not be empty.");
    }

    const fs::path source(inputPath);
    const fs::path destination(outputPath);
    if (fs::is_regular_file(source)) {
        decryptSingleFile(source, destination, password);
        return {1, 0};
    }
    if (fs::is_directory(source)) {
        return processDirectory(source, destination, password, false);
    }
    throw std::runtime_error("Input path is neither a regular file nor a directory: " + inputPath);
}

FileMetadata inspectFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Unable to open input file: " + path);
    }

    std::vector<unsigned char> header(serializedHeaderSize());
    // Inspect deliberately stops after the header; it never touches the password path.
    input.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    header.resize(static_cast<size_t>(input.gcount()));
    return parseEnvelopeHeader(header).metadata;
}

std::string toHex(const std::vector<unsigned char>& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (unsigned char value : bytes) {
        result.push_back(kHex[(value >> 4) & 0x0f]);
        result.push_back(kHex[value & 0x0f]);
    }
    return result;
}

}  // namespace securecrypto
