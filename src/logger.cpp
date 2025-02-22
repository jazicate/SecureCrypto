#include "logger.h"
#include <iostream>

/**
 * Logs a message to the console, prefixing it with "[LOG]: " to make it clear
 * that it's a log message.
 *
 * @param message The message to be logged.
 */
void Logger::log(const std::string &message) {
	std::cout << "[LOG]: " << message << std::endl;
}