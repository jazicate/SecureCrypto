#include "logger.h"
#include <iostream>

<<<<<<< HEAD
/**
 * Logs a message to the console, prefixing it with "[LOG]: " to make it clear
 * that it's a log message.
 *
 * @param message The message to be logged.
 */
=======
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21
void Logger::log(const std::string &message) {
	std::cout << "[LOG]: " << message << std::endl;
}