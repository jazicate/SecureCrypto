#ifndef CLI_H
#define CLI_H

namespace cli {

// Parses command-line arguments and dispatches to encrypt/decrypt/inspect.
int run(int argc, char* argv[]);

}  // namespace cli

#endif
