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

class OpensslException : public std::runtime_error
{
public:
	OpensslException(const std::string &err) : runtime_error(err) {}
};

class KeyGenerationException : public OpensslException
{
public:
	KeyGenerationException(const std::string &err) : OpensslException(err) {}
};

class KeyConversionException : public OpensslException
{
public:
	KeyConversionException(const std::string &err) : OpensslException(err) {}
};

class FingerprintComparisonException : public std::runtime_error
{
public:
	FingerprintComparisonException(const std::string &err) : runtime_error(err) {}
};

class InterfaceException : public std::runtime_error
{
public:
	InterfaceException(const std::string &err) : runtime_error(err) {}
};

class SelectionException : public std::runtime_error
{
public:
	SelectionException(const std::string &err) : runtime_error(err) {}
};