#pragma once

#include <stdexcept>

class LoggingException : public std::runtime_error
{
public:
	LoggingException(const std::string &err) : runtime_error(err) {}
};

class NetworkException : public std::runtime_error
{
public:
	NetworkException(const std::string &err) : runtime_error(err) {}
};

class NetworkStartupException : public NetworkException
{
public:
	NetworkStartupException(const std::string &err) : NetworkException(err) {}
};
