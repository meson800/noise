#include <thread>

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
#include <openssl/ec.h>
#include <openssl/sha.h>

}

std::map<int, std::mutex> Crypto::cryptoMuxes;

static void locking_function(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
	{
		std::cout << "Locking crypto mutex " << n << " with filename " << file << " line:" << line << std::endl;
		Crypto::cryptoMuxes[n].lock();
	} else {
		if (Crypto::cryptoMuxes.count(n))
		{
			std::cout << "Unlocking crypto mutex " << n << " with filename " << file << " line:" << line << std::endl;
			Crypto::cryptoMuxes[n].unlock();
		}
	}
}

static unsigned long simple_id_function(void)
{
	std::hash<std::thread::id> hasher;
	return hasher(std::this_thread::get_id());
}

static void id_function(openssl::CRYPTO_THREADID * id)
{
	std::hash<std::thread::id> hasher;
	openssl::CRYPTO_THREADID_set_numeric, hasher(std::this_thread::get_id());
}

Crypto::Crypto()
{
	Log::writeToLog(Log::INFO, "Initalizing crypto...");
	//init openssl
	openssl::ERR_load_crypto_strings();
	openssl::OpenSSL_add_all_algorithms();
	openssl::OPENSSL_config(NULL);
	//init threading code
	/*
	openssl::CRYPTO_THREADID_set_callback(id_function);
	openssl::CRYPTO_set_id_callback(simple_id_function);
	openssl::CRYPTO_set_locking_callback(locking_function);
	*/
	//seed random number generator
	openssl::RAND_poll();

	if (!(keyContext = openssl::EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)))
		throw OpensslException("Can't create key generation context");
	//init key generation
	if (!openssl::EVP_PKEY_keygen_init(keyContext))
		throw OpensslException("Can't initalize key generation");
	if (!openssl::EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext, 4096))
		throw OpensslException("Can't set number of bits in RSA key");

	//set up ephemeral key generation
	if (NULL == (ephemeralParamContext = openssl::EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
		throw OpensslException("Can't create new ephemeral parameter context");
	if (1 != openssl::EVP_PKEY_paramgen_init(ephemeralParamContext))
		throw OpensslException("Can't init ephemeral parameter context");
	if (1 != openssl::EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ephemeralParamContext, NID_X9_62_prime256v1))
		throw OpensslException("Can't set ephemeral parameter curve");
	if (!openssl::EVP_PKEY_paramgen(ephemeralParamContext, &ephemeralKeyParams))
		throw OpensslException("Can't generate ephemeral key generation params");
	if (NULL == (ephemeralKeyContext = openssl::EVP_PKEY_CTX_new(ephemeralKeyParams, NULL)))
		throw OpensslException("Can't generate ephemeral key generation context");
	if (1 != openssl::EVP_PKEY_keygen_init(ephemeralKeyContext))
		throw OpensslException("Can't init ephemeral key generation context");

	Log::writeToLog(Log::INFO, "Done initalizing crypto");
}

Crypto::~Crypto()
{
	//free contexts
	openssl::EVP_PKEY_CTX_free(keyContext);
	openssl::EVP_PKEY_CTX_free(ephemeralParamContext);
	openssl::EVP_PKEY_CTX_free(ephemeralParamContext);
	openssl::EVP_PKEY_free(ephemeralKeyParams);

	//free crypto locks
	openssl::CRYPTO_set_id_callback(nullptr);
	openssl::CRYPTO_set_id_callback(nullptr);
	openssl::CRYPTO_set_locking_callback(nullptr);
}

void Crypto::generateKeypair(openssl::EVP_PKEY ** key)
{
	Log::writeToLog(Log::INFO, "Generating RSA keypair");
	if (!keyContext)
		throw KeyGenerationException("Can't generate keypair, no key context");
	if (!openssl::EVP_PKEY_keygen(keyContext, key))
		throw KeyGenerationException("Key generation failed");
}

void Crypto::generateEphemeralKeypair(openssl::EVP_PKEY ** key)
{
	*key = openssl::EVP_PKEY_new();
	Log::writeToLog(Log::INFO, "Generating ephemeral EC keypair");
	if (!ephemeralKeyContext)
		throw KeyGenerationException("Can't generate ephemeral EC keypair, no context");
	if (!openssl::EVP_PKEY_keygen(ephemeralKeyContext, key))
		throw KeyGenerationException("Ephemeral key generation failed");
}

std::vector<unsigned char> Crypto::signMessage(openssl::EVP_PKEY * key, const std::vector<unsigned char>& message)
{
	openssl::EVP_MD_CTX* digestContext = 0;
	//create and init the context
	if (!(digestContext = openssl::EVP_MD_CTX_create()))
		throw OpensslException("Couldn't create message signing context");
	if (1 != openssl::EVP_DigestSignInit(digestContext, NULL, openssl::EVP_sha256(), NULL, key))
		throw OpensslException("Couldn't init message signing");

	//sign message
	if (1 != openssl::EVP_DigestSignUpdate(digestContext, message.data(), message.size()))
		throw OpensslException("Couldn't sign message");

	//call finalization with buffer = null to get length of signature
	size_t signatureLength = 0;
	if (1 != openssl::EVP_DigestSignFinal(digestContext, NULL, &signatureLength))
		throw OpensslException("Couldn't finalize signature");

	//allocate memory for signature
	unsigned char* tempBuffer = new unsigned char[signatureLength];
	//and get the signature
	if (1 != openssl::EVP_DigestSignFinal(digestContext, tempBuffer, &signatureLength))
		throw OpensslException("Couldn't extract signature");

	//Now init result
	std::vector<unsigned char> result(tempBuffer, tempBuffer + signatureLength);
	return result;
}

bool Crypto::verifySignature(openssl::EVP_PKEY * key, const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature)
{
	openssl::EVP_MD_CTX* digestContext = 0;
	//create and init the context
	if (!(digestContext = openssl::EVP_MD_CTX_create()))
		throw OpensslException("Couldn't create message signing context");
	//Init verification operation
	if (1 != openssl::EVP_DigestVerifyInit(digestContext, NULL, openssl::EVP_sha256(), NULL, key))
		throw OpensslException("Couldn't start the verification process");
	if (1 != openssl::EVP_DigestVerifyUpdate(digestContext, message.data(), message.size()))
		throw OpensslException("Couldn't verify message");

	//verify signature
	size_t size = signature.size();
	if (1 == openssl::EVP_DigestVerifyFinal(digestContext, (unsigned char*)signature.data(), size))
	{
		return true;
	}
	return false;
}
void Crypto::deriveSharedKey(openssl::EVP_PKEY * key, openssl::EVP_PKEY * otherKey, 
	SymmetricKey& sharedKey)
{
	openssl::EVP_PKEY_CTX* derivationContext = 0;
	//start derivation context
	if (NULL == (derivationContext = openssl::EVP_PKEY_CTX_new(key,NULL)))
		throw OpensslException("Can't create key derivation context");
	if (1 != openssl::EVP_PKEY_derive_init(derivationContext))
		throw OpensslException("Can't init key derivation context");
	//set other key
	if (1 != openssl::EVP_PKEY_derive_set_peer(derivationContext, otherKey))
		throw OpensslException("Can't set other peer key in key derivation");

	//determine shared secret length
	size_t secretSize = 0;
	if (1 != openssl::EVP_PKEY_derive(derivationContext, NULL, &secretSize))
		throw OpensslException("Can't derive shared secret");
	//create temp buffer
	unsigned char* tempBuffer = new unsigned char[secretSize];

	if (1 != openssl::EVP_PKEY_derive(derivationContext, tempBuffer, &secretSize))
		throw OpensslException("Can't derive shared secret");

	std::vector<unsigned char> sharedSecret = std::vector<unsigned char>(tempBuffer, tempBuffer + secretSize);
	//deallocate stuff
	EVP_PKEY_CTX_free(derivationContext);
	EVP_PKEY_free(key);
	EVP_PKEY_free(otherKey);

	//Hash the shared secret to derive a secure key
	unsigned char* sharedKeyBuffer = new unsigned char[SHA512_DIGEST_LENGTH];
	openssl::SHA512(tempBuffer, secretSize, sharedKeyBuffer);
	sharedKey.key = std::vector<unsigned char>(sharedKeyBuffer, sharedKeyBuffer + 32);
	sharedKey.iv = std::vector<unsigned char>(sharedKeyBuffer + 32, sharedKeyBuffer + 32 + 16);
	delete[](tempBuffer);
	delete[](sharedKeyBuffer);
}

std::vector<unsigned char> Crypto::encryptSymmetric(const SymmetricKey& key, const std::vector<unsigned char>& plaintext)
{
	Log::writeToLog(Log::L_DEBUG, "Encrypting plaintext of length ", plaintext.size(), " with key ", key.toString());;
	openssl::EVP_CIPHER_CTX* cipherContext = 0;
	//init context
	if (NULL == (cipherContext = openssl::EVP_CIPHER_CTX_new()))
		throw OpensslException("Couldn't create cipher context");
	if (1 != openssl::EVP_EncryptInit_ex(cipherContext, openssl::EVP_aes_256_cbc(), NULL, key.key.data(), key.iv.data()))
		throw OpensslException("Couldn't init symmetric encryption");

	//create buffer large enough for ciphertext. Let's make it ciphertext + 1024, just in case
	unsigned char * ciphertextBuffer = new unsigned char[plaintext.size() + 1024];

	int usedLength = 0;
	if (1 != openssl::EVP_EncryptUpdate(cipherContext, ciphertextBuffer, &usedLength, plaintext.data(), plaintext.size()))
		throw OpensslException("Couldn't encrypt plaintext");
	//Finalize encryption. Additional ciphertext can be written, for padding
	int additionalLength = 0;
	if (1 != openssl::EVP_EncryptFinal(cipherContext, ciphertextBuffer + usedLength, &additionalLength))
		throw OpensslException("Couldn't finalize encryption");
	usedLength += additionalLength;

	//copy resultant
	std::vector<unsigned char> ciphertext = std::vector<unsigned char>(ciphertextBuffer, ciphertextBuffer + usedLength);
	//cleanup
	openssl::EVP_CIPHER_CTX_free(cipherContext);
	delete[](ciphertextBuffer);

	Log::writeToLog(Log::L_DEBUG, "Encrypted plaintext into ciphertext of length ", ciphertext.size());

	return ciphertext;
}

std::vector<unsigned char> Crypto::decryptSymmetric(const SymmetricKey& key, const std::vector<unsigned char>& ciphertext)
{
	Log::writeToLog(Log::L_DEBUG, "Decrypting ciphertext of length ", ciphertext.size(), " with key ", key.toString());
	openssl::EVP_CIPHER_CTX* cipherContext = 0;
	//init context
	if (NULL == (cipherContext = openssl::EVP_CIPHER_CTX_new()))
		throw OpensslException("Couldn't create cipher context");
	if (1 != openssl::EVP_DecryptInit_ex(cipherContext, openssl::EVP_aes_256_cbc(), NULL, key.key.data(), key.iv.data()))
		throw OpensslException("Couldn't init symmetric decryption");

	//do main decryption
	unsigned char * plaintextBuffer = new unsigned char[ciphertext.size() + 1024];

	int usedLength = 0;
	if (1 != openssl::EVP_DecryptUpdate(cipherContext, plaintextBuffer, &usedLength, ciphertext.data(), ciphertext.size()))
		throw OpensslException("Couldn't decrypt ciphertext");

	//finalize decryption. Additional plaintext can be written, so account for it
 	int additionalLength = 0;
	if (1 != openssl::EVP_DecryptFinal(cipherContext, plaintextBuffer + usedLength, &additionalLength))
		throw OpensslException("Couldn't finalize decryption");
	usedLength += additionalLength;
	
	//get result
	std::vector<unsigned char> plaintext = std::vector<unsigned char>(plaintextBuffer, plaintextBuffer + usedLength);
	//cleanup
	openssl::EVP_CIPHER_CTX_free(cipherContext);
	delete[](plaintextBuffer);

	Log::writeToLog(Log::L_DEBUG, "Decrypted into plaintext of length ", plaintext.size());
	
	return plaintext;
}

Envelope Crypto::encryptAsymmetric(openssl::EVP_PKEY ** publicKey, std::vector<unsigned char> plaintext)
{
	Envelope envelope;

	//init context
	openssl::EVP_CIPHER_CTX* cipherContext;
	if (NULL == (cipherContext = openssl::EVP_CIPHER_CTX_new()))
		throw OpensslException("Couldn't create encryption context");

	//create temp buffers for encrypted key and iv
	unsigned char* tempEncryptedKey = new unsigned char[1024];
	int encryptedKeyLength = 0;
	unsigned char* tempIv = new unsigned char[512];
	//init envelope creation
	if (1 != openssl::EVP_SealInit(cipherContext, openssl::EVP_aes_256_cbc(), &tempEncryptedKey, 
		&encryptedKeyLength, tempIv, publicKey, 1))
		throw OpensslException("Couldn't start envelope encryption");

	//create temp buffer for ciphertext
	unsigned char* tempCiphertext = new unsigned char[plaintext.size() + 1024];

	int usedLength = 0;
	if (1 != openssl::EVP_SealUpdate(cipherContext, tempCiphertext, &usedLength, plaintext.data(), plaintext.size()))
		throw OpensslException("Couldn't encrypt plaintext into envelope");

	int additionalLength = 0;
	//finalize envelope, additional ciphertext can be written
	if (1 != openssl::EVP_SealFinal(cipherContext, tempCiphertext + usedLength, &additionalLength))
		throw OpensslException("Couldn't finalize envelope creation");

	usedLength += additionalLength;

	//now copy into envelope
	envelope.ciphertext = std::vector<unsigned char>(tempCiphertext, tempCiphertext + usedLength);
	envelope.sessionKey = std::vector<unsigned char>(tempEncryptedKey, tempEncryptedKey + encryptedKeyLength);
	envelope.iv = std::vector<unsigned char>(tempIv, tempIv + 16);

	//cleanup
	openssl::EVP_CIPHER_CTX_free(cipherContext);
	delete[](tempEncryptedKey);
	delete[](tempIv);
	delete[](tempCiphertext);

	return envelope;
}

std::vector<unsigned char> Crypto::decryptAsymmetric(openssl::EVP_PKEY * key, const Envelope & envelope)
{
	//init context
	openssl::EVP_CIPHER_CTX* cipherContext;
	if (NULL == (cipherContext = openssl::EVP_CIPHER_CTX_new()))
		throw OpensslException("Couldn't create encryption context");

	//init decryption
	if (1 != openssl::EVP_OpenInit(cipherContext, openssl::EVP_aes_256_cbc(), envelope.sessionKey.data(),
		envelope.sessionKey.size(), envelope.iv.data(), key))
		throw OpensslException("Couldn't init envelope decryption");

	//create temp storage for plaintext
	unsigned char* tempPlaintext = new unsigned char[envelope.ciphertext.size() + 1024];
	int usedLength = 0;

	//decrypt
	if (1 != openssl::EVP_OpenUpdate(cipherContext, tempPlaintext, &usedLength, 
		envelope.ciphertext.data(), envelope.ciphertext.size()))
		throw OpensslException("Couldn't decrypt envelope");

	//Finalize decryption. This might write additional plaintext!
	int additionalLength = 0;
	if (1 != openssl::EVP_OpenFinal(cipherContext, tempPlaintext + usedLength, &additionalLength))
		throw OpensslException("Couldn't finalize envelope decryption");

	usedLength += additionalLength;
	//copy result
	std::vector<unsigned char> plaintext = std::vector<unsigned char>(tempPlaintext, tempPlaintext + usedLength);

	//cleanup
	openssl::EVP_CIPHER_CTX_free(cipherContext);
	delete[](tempPlaintext);
	
	return plaintext;
}

SymmetricKey Crypto::deriveKeyFromPassword(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& password)
{
	SymmetricKey resultKey;

	unsigned char* tempKey = new unsigned char[256];
	unsigned char* iv = new unsigned char[16];

	unsigned int keyLength = 0;
	if (0 == (keyLength = openssl::EVP_BytesToKey(openssl::EVP_aes_256_cbc(), openssl::EVP_sha1(), salt.data(),
		password.data(), password.size(), 1, tempKey, iv)))
		throw OpensslException("Couldn't extract key and iv from password");

	resultKey.key = std::vector<unsigned char>(tempKey, tempKey + keyLength);
	resultKey.iv = std::vector<unsigned char>(iv, iv + 16);

	delete[](tempKey);
	delete[](iv);

	return resultKey;
}
