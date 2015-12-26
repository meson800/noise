#pragma once

#include <stdexcept>

class LoggingException : public std::runtime_error
{
public:
	LoggingException(const std::string &err) : runtime_error(err) {}
};
