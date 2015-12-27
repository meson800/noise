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

class FatalException : public std::runtime_error
{
public:
	FatalException(const std::string &err) : runtime_error(err) {}
};

class NetworkStartupException : public FatalException
{
public:
	NetworkStartupException(const std::string &err) : FatalException(err) {}
};

class NetworkConnectionException : public NetworkException
{
public:
	NetworkConnectionException(const std::string &err) : NetworkException(err) {}
};