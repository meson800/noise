#include "LocalNoiseInterface.h"

#include "Network.h"
#include "Crypto.h"
#include "CryptoHelpers.h"
#include "Exceptions.h"

#include <RakPeerInterface.h>
#include <MessageIdentifiers.h>
#include "Messages.h"
#include <BitStream.h>
#include "Log.h"

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
		{
			mux.unlock();
			handlePacket();
		}
		else
		{
			mux.unlock();
			return;
		}
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
		mux.unlock();
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
				//now create a fingerprint
				Fingerprint fingerprint = Fingerprint(bsIn);
				Log::writeToLog(Log::INFO, "Recieved fingerprint ", fingerprint.toString());
				//See if we need that fingerprint
				if (otherEncryptionKeys[fingerprint] == 0)
					requestPublickey(fingerprint, packet->guid);
				break;
			}

			case ID_REQUEST_PUBKEY:
			{
				RakNet::BitStream bsIn(packet->data, packet->length, false);
				bsIn.IgnoreBytes(sizeof(RakNet::MessageID));
				//now create a fingerprint
				Fingerprint fingerprint = Fingerprint(bsIn);
				Log::writeToLog(Log::INFO, "Recieved public key request for key ", fingerprint.toString());
				//if we have it, let's send it
				mux.lock();
				if (ourEncryptionKeys.count(fingerprint))
				{
					mux.unlock();
					sendPublickey(fingerprint, packet->guid);
				}
				else
					mux.unlock();
				break;
			}

			case ID_SEND_PUBKEY:
			{
				RakNet::BitStream bsIn(packet->data, packet->length, false);
				bsIn.IgnoreBytes(sizeof RakNet::MessageID);
				//recieve bytes
				std::vector<unsigned char> pubkeyData;
				unsigned char cur = 0;
				while (bsIn.Read(cur))
				{
					pubkeyData.push_back(cur);
				}
				//convert to a key
				openssl::EVP_PKEY* newKey = CryptoHelpers::bytesToOslPublicKey(pubkeyData);
				//get it's fingerprint
				Fingerprint fingerprint = Fingerprint(newKey);
				Log::writeToLog(Log::INFO, "Recieved public key ", fingerprint.toString());
				//insert into our map!
				otherEncryptionKeys[fingerprint] = newKey;
			}

			default:
				break;
			}
			network->deallocatePacket(packet);
		}
	}
	else
		mux.unlock();
}

void LocalNoiseInterface::requestPublickey(const Fingerprint & fingerprint, RakNet::RakNetGUID system)
{
	Log::writeToLog(Log::INFO, "Requesting public key ", fingerprint.toString());
	RakNet::BitStream bs;
	bs.Write((RakNet::MessageID)ID_REQUEST_PUBKEY);
	fingerprint.toBitStream(bs);
	mux.lock();
	network->sendBitStream(&bs, system, false);
	mux.unlock();
}

void LocalNoiseInterface::sendPublickey(const Fingerprint & fingerprint, RakNet::RakNetGUID system)
{
	mux.lock();
	if (ourEncryptionKeys.count(fingerprint))
	{
		std::vector<unsigned char> pubkey = CryptoHelpers::oslPublicKeyToBytes(ourEncryptionKeys[fingerprint]);
		Log::writeToLog(Log::INFO, "Sending public key ", fingerprint.toString());
		RakNet::BitStream bs;
		bs.Write((RakNet::MessageID)ID_SEND_PUBKEY);
		for (unsigned int i = 0; i < pubkey.size(); ++i)
			bs.Write(pubkey[i]);
		network->sendBitStream(&bs, system, false);
		mux.unlock();
	}
	else
	{
		mux.unlock();
	}
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
	Log::writeToLog(Log::INFO, "Advertising public key ", fingerprint.toString());
	RakNet::BitStream bs;
	bs.Write((RakNet::MessageID)ID_OFFER_PUBKEY);
	fingerprint.toBitStream(bs);
	mux.lock();
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
