#include "cli.h"

#include "logger.h"
#include "secure_crypto.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <termios.h>

namespace cli {
namespace {

void printUsage() {
    std::cout << "securecrypto: authenticated file encryption demo\n\n"
              << "Usage:\n"
              << "  securecrypto encrypt --in <file|dir> --out <file|dir> [--password <secret>]\n"
              << "  securecrypto decrypt --in <file|dir> --out <file|dir> [--password <secret>]\n"
              << "  securecrypto inspect --in <file>\n";
}

std::unordered_map<std::string, std::string> parseOptions(int argc, char* argv[], int startIndex) {
    std::unordered_map<std::string, std::string> options;
    // Options are expected in "--flag value" pairs.
    for (int i = startIndex; i < argc; i += 2) {
        if (i + 1 >= argc) {
            throw std::invalid_argument("Missing value for option: " + std::string(argv[i]));
        }

        const std::string key = argv[i];
        if (key.rfind("--", 0) != 0) {
            throw std::invalid_argument("Unexpected argument: " + key);
        }

        options[key] = argv[i + 1];
    }
    return options;
}

const std::string& requireOption(const std::unordered_map<std::string, std::string>& options,
                                 const std::string& name) {
    const auto it = options.find(name);
    if (it == options.end() || it->second.empty()) {
        throw std::invalid_argument("Missing required option: " + name);
    }
    return it->second;
}

std::string promptPassword(const std::string& prompt) {
    // Hiding terminal echo stops the password from being shown as it is typed.
    if (!isatty(STDIN_FILENO)) {
        throw std::invalid_argument("Password was not provided and stdin is not interactive.");
    }

    std::cout << prompt;
    std::cout.flush();

    termios currentSettings {};
    if (tcgetattr(STDIN_FILENO, &currentSettings) != 0) {
        throw std::runtime_error("Failed to read terminal settings for password input.");
    }

    termios hiddenSettings = currentSettings;
    hiddenSettings.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &hiddenSettings) != 0) {
        throw std::runtime_error("Failed to disable terminal echo for password input.");
    }

    std::string password;
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &currentSettings);
    std::cout << "\n";

    if (!std::cin) {
        throw std::runtime_error("Failed to read password from terminal.");
    }

    return password;
}

std::string resolvePassword(const std::unordered_map<std::string, std::string>& options, bool confirmPassword) {
    const auto it = options.find("--password");
    if (it != options.end()) {
        if (it->second.empty()) {
            throw std::invalid_argument("Password must not be empty.");
        }
        return it->second;
    }

    // Prompting keeps the password out of shell history when someone uses the tool manually.
    const std::string password = promptPassword("Enter password: ");
    if (password.empty()) {
        throw std::invalid_argument("Password must not be empty.");
    }

    if (confirmPassword) {
        const std::string confirmation = promptPassword("Confirm password: ");
        if (password != confirmation) {
            throw std::invalid_argument("Passwords did not match.");
        }
    }

    return password;
}

int runEncrypt(const std::unordered_map<std::string, std::string>& options) {
    const std::string& input = requireOption(options, "--in");
    const std::string& output = requireOption(options, "--out");
    const std::string password = resolvePassword(options, true);
    const auto stats = securecrypto::encryptPath(input, output, password);
    // The stats make directory operations less mysterious to the user.
    Logger::log("Encryption completed. Files: " + std::to_string(stats.filesProcessed) +
                ", directories: " + std::to_string(stats.directoriesProcessed));
    return 0;
}

int runDecrypt(const std::unordered_map<std::string, std::string>& options) {
    const std::string& input = requireOption(options, "--in");
    const std::string& output = requireOption(options, "--out");
    const std::string password = resolvePassword(options, false);
    const auto stats = securecrypto::decryptPath(input, output, password);
    Logger::log("Decryption completed. Files: " + std::to_string(stats.filesProcessed) +
                ", directories: " + std::to_string(stats.directoriesProcessed));
    return 0;
}

int runInspect(const std::unordered_map<std::string, std::string>& options) {
    const std::string& input = requireOption(options, "--in");
    const auto metadata = securecrypto::inspectFile(input);
    // Inspect is just a header dump; it never tries to decrypt the payload.
    std::cout
        << "version: " << static_cast<int>(metadata.version) << "\n"
        << "plaintext_size: " << metadata.plaintextSize << "\n"
        << "ciphertext_size: " << metadata.ciphertextSize << "\n"
        << "scrypt_n: " << metadata.scrypt.n << "\n"
        << "scrypt_r: " << metadata.scrypt.r << "\n"
        << "scrypt_p: " << metadata.scrypt.p << "\n"
        << "scrypt_maxmem: " << metadata.scrypt.maxMemoryBytes << "\n"
        << "salt: " << securecrypto::toHex(metadata.salt) << "\n"
        << "nonce: " << securecrypto::toHex(metadata.nonce) << "\n"
        << "tag: " << securecrypto::toHex(metadata.tag) << "\n";
    return 0;
}

}  // namespace

int run(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    const std::string command = argv[1];
    if (command == "help" || command == "--help" || command == "-h") {
        printUsage();
        return 0;
    }

    try {
        const auto options = parseOptions(argc, argv, 2);
        // Each command hands off to a small helper so the branching stays readable.
        if (command == "encrypt") {
            return runEncrypt(options);
        }
        if (command == "decrypt") {
            return runDecrypt(options);
        }
        if (command == "inspect") {
            return runInspect(options);
        }

        throw std::invalid_argument("Unknown command: " + command);
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n\n";
        printUsage();
        return 1;
    }
}

}  // namespace cli
