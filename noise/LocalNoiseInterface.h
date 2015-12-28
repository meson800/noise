#pragma once

#include "NoiseInterface.h"
#include "Fingerprint.h"
#include <RakNetTypes.h>

class Network;
class Crypto;

#include <mutex>
#include <map>

namespace openssl
{
	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

class LocalNoiseInterface : public NoiseInterface
{
public:
	LocalNoiseInterface();
	~LocalNoiseInterface();
	//----------Networking functions-----------------
	//-----------------------------------------------

	//Starts the networking dameon
	void startNetworking(int portNumber) override;
	//Stops the networking dameon
	void stopNetworking(void) override;
	//checks if running
	bool isRunning(void) override;
	//Connects to a node
	void connectToNode(const std::string& address, int port = SERVER_PORT) override;
	//Advertises one of our encryption public keys
	void advertiseOurPublicKey(const Fingerprint& fingerprint) override;

	//---------Cryptography Functions----------------
	//-----------------------------------------------

	//generates new non-ephemeral encryption key, returns fingerprint for key
	Fingerprint generateNewEncryptionKey() override;
	//Returns the number of non-ephemeral keypairs we have
	unsigned int numEncryptionKeys() override;

private:
	//Handles a single packet in the queue
	void handlePacket(void);

	std::mutex mux;

	Network* network;
	Crypto* crypto;

	std::map<Fingerprint, openssl::EVP_PKEY*> ourEncryptionKeys;
	std::map<Fingerprint, openssl::EVP_PKEY*> otherEncryptionKeys;
	std::map<RakNet::RakNetGUID, std::vector<Fingerprint>> nodes;
};