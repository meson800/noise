#include "CryptoHelpers.h"
#include "Exceptions.h"
#include "Log.h"
#include <stdlib.h>

#include "Crypto.h"

namespace openssl {
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
}

std::vector<unsigned char> CryptoHelpers::oslPublicKeyToBytes(openssl::EVP_PKEY * key)
{
	std::lock_guard<std::mutex> lock(Crypto::cryptoLock);

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
	//free the key
	openssl::RSA_free(rsaKey);

	return bytes;
}

openssl::EVP_PKEY * CryptoHelpers::bytesToOslPublicKey(const std::vector<unsigned char>& bytes)
{
	std::lock_guard<std::mutex> lock(Crypto::cryptoLock);

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

std::vector<unsigned char> CryptoHelpers::oslPrivateKeyToBytes(openssl::EVP_PKEY * key)
{
	std::lock_guard<std::mutex> lock(Crypto::cryptoLock);

	Log::writeToLog(Log::L_DEBUG, "Converting private key to bytes");
	openssl::RSA* rsaKey = openssl::EVP_PKEY_get1_RSA(key);
	if (!rsaKey)
		throw KeyConversionException("Failed to extract key from given EVP_PKEY");
	unsigned char* rawBytes = new unsigned char[4096];
	unsigned char* tempP = rawBytes;
	//NOTE TO PROGRAMMER
	//Openssl CHANGES the pointer that you give it!!!
	//You MUST give it a temporary pointer that is initally equal to rawBytes!
	//Openssl increments the pointer it's given after it's done filling
	//so you need to keep your original pointer around
	int usedLength;
	if (!(usedLength = openssl::i2d_RSAPrivateKey(rsaKey, &tempP)))
		throw KeyConversionException("Failed to convert RSA key into bytes");
	Log::writeToLog(Log::L_DEBUG, "Converted key to ", usedLength, " bytes");

	std::vector<unsigned char> bytes(rawBytes, rawBytes + usedLength);
	//free the array
	delete[] rawBytes;
	//free the key
	openssl::RSA_free(rsaKey);

	return bytes;
}

openssl::EVP_PKEY* CryptoHelpers::bytesToOslKeypair(const std::vector<unsigned char>& privateBytes,
	const std::vector<unsigned char>& publicBytes)
{
	std::lock_guard<std::mutex> lock(Crypto::cryptoLock);

	Log::writeToLog(Log::L_DEBUG, "Converting bytes to a public key");

	const unsigned char* dataStart = privateBytes.data();
	openssl::RSA* rsaKey = openssl::d2i_RSAPrivateKey(NULL, &dataStart, privateBytes.size());
	if (!rsaKey)
		throw KeyConversionException("Failed to convert bytes to a private RSA key");

	dataStart = publicBytes.data();
	openssl::d2i_RSAPublicKey(&rsaKey, &dataStart, publicBytes.size());
	if (!rsaKey)
		throw KeyConversionException("Failed to convert bytes to a public RSA key");

	openssl::EVP_PKEY* key = openssl::EVP_PKEY_new();
	if (!openssl::EVP_PKEY_set1_RSA(key, rsaKey))
		throw KeyConversionException("Failed to convert RSA key into EVP_PKEY");

	return key;
}

std::vector<unsigned char> CryptoHelpers::ecPublicKeyToBytes(openssl::EVP_PKEY * key)
{
	std::lock_guard<std::mutex> lock(Crypto::cryptoLock);

	Log::writeToLog(Log::L_DEBUG, "Converting ephemeral key to bytes");
	openssl::EC_KEY* ecKey = openssl::EVP_PKEY_get1_EC_KEY(key);
	if (ecKey == 0)
		throw KeyConversionException("Couldn't extract ellptical curve key out of given key");

	const openssl::EC_POINT* ecPoint = openssl::EC_KEY_get0_public_key(ecKey);
	if (ecPoint == 0)
		throw KeyConversionException("Couldn't extract a curve point of of EC key");

	unsigned int bufferSize = openssl::EC_POINT_point2oct(openssl::EC_KEY_get0_group(ecKey), 
		ecPoint, openssl::POINT_CONVERSION_COMPRESSED, NULL, 0,NULL);
	unsigned char* tempBuffer = new unsigned char[bufferSize];

	openssl::EC_POINT_point2oct(openssl::EC_KEY_get0_group(ecKey),
		ecPoint, openssl::POINT_CONVERSION_COMPRESSED, tempBuffer, bufferSize, NULL);

	std::vector<unsigned char> result = std::vector<unsigned char>(tempBuffer, tempBuffer + bufferSize);

	delete[](tempBuffer);
	openssl::EC_KEY_free(ecKey);
	
	return result;
}

openssl::EVP_PKEY * CryptoHelpers::bytesToEcPublicKey(const std::vector<unsigned char>& bytes)
{
	std::lock_guard<std::mutex> lock(Crypto::cryptoLock);

	Log::writeToLog(Log::L_DEBUG, "Converting bytes to a EC key");

	//get group from named curve
	openssl::EC_GROUP* group = 0;
	if (NULL == (group = openssl::EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
		throw OpensslException("Couldn't get group from named curve");

	openssl::EC_POINT* point = 0;
	if (NULL == (point = openssl::EC_POINT_new(group)))
		throw OpensslException("Couldn't init point from group");
	if (1 != openssl::EC_POINT_oct2point(group, point, bytes.data(), bytes.size(), NULL))
		throw OpensslException("Couldn't extract point from bytes");
	openssl::EC_KEY* key = 0;

	if (NULL == (key = openssl::EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
		throw OpensslException("Couldn't init new ec key");
	//generate key
	if (1 != openssl::EC_KEY_set_public_key(key, point))
		throw OpensslException("Couldn't create EC key from point");

	//and finally generate EVP_PKEY
	openssl::EVP_PKEY* finalKey = 0;
	if (NULL == (finalKey = openssl::EVP_PKEY_new()))
		throw OpensslException("Couldn't init new PKEY");
	if (1 != openssl::EVP_PKEY_set1_EC_KEY(finalKey, key))
		throw OpensslException("Couldn't generate PKEY from EC key");


	//cleanup
	openssl::EC_GROUP_free(group);
	openssl::EC_POINT_free(point);
	openssl::EC_KEY_free(key);

	return finalKey;
}
