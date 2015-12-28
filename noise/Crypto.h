#pragma once

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
	void generateKeypair(openssl::EVP_PKEY* key);

private:
	openssl::EVP_PKEY_CTX* paramContext;
	openssl::EVP_PKEY_CTX* keyContext;
	openssl::EVP_PKEY* generationParams;
};