#include "Crypto.h"
#include "Exceptions.h"
#include "Log.h"

namespace openssl {
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/opensslconf.h>
#include <openssl/conf.h>
#include <openssl/err.h>

}

Crypto::Crypto()
{
	Log::writeToLog(Log::INFO, "Initalizing crypto...");
	//init openssl
	openssl::ERR_load_crypto_strings();
	openssl::OpenSSL_add_all_algorithms();
	openssl::OPENSSL_config(NULL);
	//seed random number generator
	openssl::RAND_poll();

	if (!(keyContext = openssl::EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)))
		throw OpensslException("Can't create key generation context");
	//init key generation
	if (!openssl::EVP_PKEY_keygen_init(keyContext))
		throw OpensslException("Can't initalize key generation");
	if (!openssl::EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext, 4096))
		throw OpensslException("Can't set number of bits in RSA key");
	Log::writeToLog(Log::INFO, "Done initalizing crypto");
}

void Crypto::generateKeypair(openssl::EVP_PKEY * key)
{
	Log::writeToLog(Log::INFO, "Generating RSA keypair");
	if (!keyContext)
		throw KeyGenerationException("Can't generate keypair, no key context");
	if (!openssl::EVP_PKEY_keygen(keyContext, &key))
		throw KeyGenerationException("Key generation failed");
}
