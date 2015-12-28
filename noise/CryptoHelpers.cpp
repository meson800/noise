#include "CryptoHelpers.h"
#include "Exceptions.h"
#include "Log.h"
#include <stdlib.h>

namespace openssl {
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
}

std::vector<unsigned char> CryptoHelpers::oslPublicKeyToBytes(openssl::EVP_PKEY * key)
{
	Log::writeToLog(Log::L_DEBUG, "Converting public key to bytes");
	openssl::RSA* rsaKey = openssl::EVP_PKEY_get1_RSA(key);
	if (!rsaKey)
		throw KeyConversionException("Failed to extract key from given EVP_PKEY");
	unsigned char* rawBytes = new unsigned char[1024];
	unsigned char* tempP = rawBytes;
	//NOTE TO PROGRAMMER
	//Openssl CHANGES the pointer that you give it!!!
	//You MUST give it a temporary pointer that is initally equal to rawBytes!
	//Openssl increments the pointer it's given after it's done filling
	//so you need to keep your original pointer around
	int usedLength;
	if (!(usedLength = openssl::i2d_RSAPublicKey(rsaKey, &tempP)))
		throw KeyConversionException("Failed to convert RSA key into bytes");
	Log::writeToLog(Log::L_DEBUG, "Converted key to ", usedLength, " bytes");

	std::vector<unsigned char> bytes(rawBytes, rawBytes + usedLength);
	//free the array
	delete[] rawBytes;

	return bytes;
}

openssl::EVP_PKEY * CryptoHelpers::bytesToOslPublicKey(const std::vector<unsigned char>& bytes)
{
	Log::writeToLog(Log::L_DEBUG, "Converting bytes to a public key");

	const unsigned char* dataStart = bytes.data();
	openssl::RSA* rsaKey = openssl::d2i_RSAPublicKey(NULL, &dataStart, bytes.size());
	if (!rsaKey)
		throw KeyConversionException("Failed to convert bytes to a RSA key");

	openssl::EVP_PKEY* key = openssl::EVP_PKEY_new();
	if (!openssl::EVP_PKEY_set1_RSA(key, rsaKey))
		throw KeyConversionException("Failed to convert RSA key into EVP_PKEY");

	return key;
}
