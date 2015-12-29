#pragma once

#include <vector>

namespace openssl
{
	struct evp_pkey_ctx_st;
	typedef evp_pkey_ctx_st EVP_PKEY_CTX;

	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

class Crypto
{
public:
	//Initalizes the random pool and generates parameters for key generation
	Crypto();
	~Crypto();
	void generateKeypair(openssl::EVP_PKEY** key);
	void generateEphemeralKeypair(openssl::EVP_PKEY** key);
	std::vector<unsigned char> signMessage(openssl::EVP_PKEY* key, const std::vector<unsigned char>& message);
	bool verifySignature(openssl::EVP_PKEY* key, const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature);
	//Derive a shared key and IV based on two ephemeral keys. This function deallocates the keys afterwards
	void deriveSharedKey(openssl::EVP_PKEY * key, openssl::EVP_PKEY * otherKey,
		std::vector<unsigned char>& sharedKeyData, std::vector<unsigned char>& sharedIv);

private:
	openssl::EVP_PKEY_CTX* keyContext;

	openssl::EVP_PKEY_CTX* ephemeralParamContext;
	openssl::EVP_PKEY_CTX* ephemeralKeyContext;
	openssl::EVP_PKEY* ephemeralKeyParams;
};