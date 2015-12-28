#include "LocalNoiseInterface.h"

#include "Network.h"
#include "Crypto.h"
#include "Exceptions.h"

LocalNoiseInterface::LocalNoiseInterface() : network(0), crypto(0)
{
	//we can init crypto at this point
	crypto = new Crypto();
}

LocalNoiseInterface::~LocalNoiseInterface()
{
	//free network and crypto
	free(network);
	free(crypto);
}

void LocalNoiseInterface::startNetworking(int portNumber)
{
	mux.lock();
	//now init network
	network = new Network(portNumber);
	network->startNode();
	mux.unlock();

	//now loop until we need to stop
	while (true)
	{
		mux.lock();
		if (network->isRunning())
			network->handlePacket();
		else
		{
			mux.unlock();
			return;
		}
		mux.unlock();
	}
}

void LocalNoiseInterface::stopNetworking(void)
{
	mux.lock();
	if (network && network->isRunning())
		network->shutdownNode();
	mux.unlock();
}

bool LocalNoiseInterface::isRunning(void)
{
	bool result = false;
	mux.lock();
	if (network)
		result = network->isRunning();
	mux.unlock();
	return result;
}

void LocalNoiseInterface::handlePacket(void)
{
	mux.lock();
	if (network && network->isRunning())
		network->handlePacket();
	mux.unlock();
}

void LocalNoiseInterface::connectToNode(const std::string & address, int port)
{
	mux.lock();
	if (network && network->isRunning())
		network->connectToNode(address, port);
	mux.unlock();

}

Fingerprint LocalNoiseInterface::generateNewEncryptionKey()
{
	mux.lock();
	if (crypto)
	{
		openssl::EVP_PKEY* newKey = 0;
		crypto->generateKeypair(&newKey);
		//get fingerprint of new key
		Fingerprint fingerprint = Fingerprint(newKey);
		//insert into our key map
		encryptionKeys[fingerprint] = newKey;
		mux.unlock();
		return fingerprint;
	}
	//if we get to this point, crypto wasn't enabled
	mux.unlock();
	throw InterfaceException("Crypto not initalized");
}

unsigned int LocalNoiseInterface::numEncryptionKeys()
{
	unsigned int result = 0;
	mux.lock();
	result = encryptionKeys.size();
	mux.unlock();
	return result;
}
