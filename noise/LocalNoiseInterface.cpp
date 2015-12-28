#include "LocalNoiseInterface.h"

#include "Network.h"
#include "Crypto.h"
#include "Exceptions.h"

#include <RakPeerInterface.h>
#include <MessageIdentifiers.h>
#include "Messages.h"
#include <BitStream.h>

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
	{
		RakNet::Packet* packet = network->handlePacket();
		if (packet)
		{
			switch (packet->data[0])
			{
			case ID_REMOTE_CONNECTION_LOST:
			case ID_REMOTE_DISCONNECTION_NOTIFICATION:
			case ID_DISCONNECTION_NOTIFICATION:
			case ID_CONNECTION_LOST:
				//remove from our list of nodes
				if (nodes.count(packet->guid))
					nodes.erase(packet->guid);
				break;

			case ID_REMOTE_NEW_INCOMING_CONNECTION:
			case ID_CONNECTION_REQUEST_ACCEPTED:
			case ID_NEW_INCOMING_CONNECTION:
				//add to our list of nodes
				nodes[packet->guid] = std::vector<Fingerprint>();
				break;

			case ID_OFFER_PUBKEY:
			{
				RakNet::BitStream bsIn(packet->data, packet->length, false);
				bsIn.IgnoreBytes(sizeof(RakNet::MessageID));
				//now we can read into a fingerprint
				std::vector<unsigned char> fingerprintData;
				unsigned char cur = 0;
				while (bsIn.Read(cur))
				{
					fingerprintData.push_back(cur);
				}
				//now create a fingerprint
				Fingerprint fingerprint = Fingerprint(fingerprintData);
				break;
			}

			default:
				break;
			}
			network->deallocatePacket(packet);
		}
	}

	mux.unlock();
}

void LocalNoiseInterface::connectToNode(const std::string & address, int port)
{
	mux.lock();
	if (network && network->isRunning())
		network->connectToNode(address, port);
	mux.unlock();

}

void LocalNoiseInterface::advertiseOurPublicKey(const Fingerprint& fingerprint)
{
	mux.lock();
	RakNet::BitStream bs;
	bs.Write((RakNet::MessageID)ID_OFFER_PUBKEY);
	for (unsigned int i = 0; i < fingerprint.data.size(); ++i)
		bs.Write(fingerprint.data[i]);
	network->sendBitStream(&bs, RakNet::UNASSIGNED_RAKNET_GUID, true);
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
		ourEncryptionKeys[fingerprint] = newKey;
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
	result = ourEncryptionKeys.size();
	mux.unlock();
	return result;
}
