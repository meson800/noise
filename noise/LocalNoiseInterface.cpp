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

namespace openssl
{
#include <openssl\rand.h>
#include <openssl\err.h>
}

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
		try
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

					//send a challenge--TEMPORARY
					sendChallenge(packet->guid, fingerprint);
					break;
				}

				case ID_CHALLENGE_PUBKEY:
				{
					RakNet::BitStream bsIn(packet->data, packet->length, false);
					bsIn.IgnoreBytes(sizeof RakNet::MessageID);
					//recieve pubkey fingerprint
					Fingerprint fingerprint = Fingerprint(bsIn);
					Log::writeToLog(Log::INFO, "Challenge recieved for pubkey ", fingerprint.toString());

					//recieve challenge
					std::vector<unsigned char> challengeData;
					unsigned char cur = 0;
					while (bsIn.Read(cur))
						challengeData.push_back(cur);
					//if we own that key, verify it
					//note that this function takes care of it
					verifyChallenge(fingerprint, challengeData, packet->guid);
					break;
				}

				case ID_VERIFY_CHALLENGE:
				{
					RakNet::BitStream bsIn(packet->data, packet->length, false);
					bsIn.IgnoreBytes(sizeof RakNet::MessageID);
					//recieve pubkey fingerprint
					Fingerprint fingerprint = Fingerprint(bsIn);
					Log::writeToLog(Log::INFO, "Recieved challenge response for pubkey ", fingerprint.toString());

					//recieve response
					std::vector<unsigned char> responseData;
					unsigned char cur = 0;
					while (bsIn.Read(cur))
						responseData.push_back(cur);

					//let's see if we have a live challenge
					mux.lock();
					//This checks if we have this public key and we have a challenge live
					if (otherEncryptionKeys.count(fingerprint) && otherEncryptionKeys[fingerprint] &&
						liveChallenges.count(fingerprint))
					{
						//try to verify
						if (crypto->verifySignature(otherEncryptionKeys[fingerprint], liveChallenges[fingerprint], responseData))
						{
							Log::writeToLog(Log::INFO, "Verified system ", packet->guid.ToString(),
								" as owning pubkey ", fingerprint.toString());
							//remove from challenges and verify
							verifiedSystems[fingerprint] = packet->guid;
							liveChallenges.erase(fingerprint);
						}
						else
						{
							Log::writeToLog(Log::INFO, "Verification failed for system ", packet->guid.ToString(),
								" and pubkey ", fingerprint.toString());
							//remove from live challenges
							liveChallenges.erase(fingerprint);
						}
					}
					else
					{
						Log::writeToLog(Log::INFO, "Didn't request challenge for pubkey ", fingerprint.toString());
					}
					mux.unlock();
					break;
				}

				case ID_SEND_EPHEMERAL_PUBKEY:
				{
					Log::writeToLog(Log::INFO, "Recieved ephemeral pubkey from system ", packet->guid.ToString());
					RakNet::BitStream bsIn(packet->data, packet->length, false);
					bsIn.IgnoreBytes(sizeof RakNet::MessageID);

					std::vector<unsigned char> recievedEphemeralKeyData;
					unsigned char cur = 0;
					while (bsIn.Read(cur))
						recievedEphemeralKeyData.push_back(cur);

					mux.lock();
					openssl::EVP_PKEY* recievedKey = CryptoHelpers::bytesToEcPublicKey(recievedEphemeralKeyData);
					otherEphemeralKeys[packet->guid] = recievedKey;
					//now that we've read a key, let's see if we have sent ours yet

					if (ourEphemeralKeys.count(packet->guid))
					{
						Log::writeToLog(Log::INFO, "Deriving shared secret with system ", packet->guid.ToString());
						//yes, we've sent our key to them. Let's derive a shared secret and send our packet along :)
						SymmetricKey sharedKey;
						crypto->deriveSharedKey(ourEphemeralKeys[packet->guid], recievedKey, sharedKey);
						sharedKeys[packet->guid] = sharedKey;
						//erase ephemeral keys, we must reset for the next packet
						ourEphemeralKeys.erase(packet->guid);
						otherEphemeralKeys.erase(packet->guid);

						//find the fingerprint that we want for the encrypted data we want to send
						Fingerprint fingerprint = outgoingData.begin()->first; //init to random fingerprint to start
						bool goodFingerprint = false;
						for (auto it = outgoingData.begin(); it != outgoingData.end(); ++it)
						{
							//pick the fingerprint for which we have a shared key
							if (verifiedSystems[it->first] == packet->guid)
							{
								fingerprint = it->first;
								goodFingerprint = true;
								break;
							}
						}
						mux.unlock();
						if (goodFingerprint)
						{
							sendEncryptedData(fingerprint);
							//Clear shared key, we used it once
							mux.lock();
							sharedKeys.erase(verifiedSystems[fingerprint]);
							mux.unlock();
						}

					}
					else
					{
						//We need to send our key along
						Log::writeToLog(Log::INFO, "Sending our ephemeral key and deriving shared secret with system ",
							packet->guid.ToString());
						//generate us a ephermeral key to send it along
						openssl::EVP_PKEY* newEphemeralKey = 0;
						crypto->generateEphemeralKeypair(&newEphemeralKey);
						//save it
						ourEphemeralKeys[packet->guid] = newEphemeralKey;
						mux.unlock();
						//we have to send before generating shared secret, as deriving destroys the keys
						sendEphemeralPublicKey(packet->guid);
						mux.lock();
						//generate shared secret 
						SymmetricKey sharedKey;
						crypto->deriveSharedKey(ourEphemeralKeys[packet->guid], recievedKey, sharedKey);
						sharedKeys[packet->guid] = sharedKey;
						//and send ours along
						mux.unlock();

					}
				}

				case ID_SEND_ENCRYPTED_DATA:
				{
					Log::writeToLog(Log::INFO, "Recieved encrypted data from system ", packet->guid.ToString());
					RakNet::BitStream bsIn(packet->data, packet->length, false);
					bsIn.IgnoreBytes(sizeof RakNet::MessageID);
					Fingerprint fingerprint = Fingerprint(bsIn);
					//read bytes in
					std::vector<unsigned char> cipherCiphertext;
					unsigned char cur = 0;
					while (bsIn.Read(cur))
						cipherCiphertext.push_back(cur);

					//decrypt it!!!
					mux.lock();
					std::vector<unsigned char> ciphertext = crypto->decryptSymmetric(sharedKeys[packet->guid], cipherCiphertext);
					//expand into envelope
					Envelope envelope = Envelope(ciphertext);
					//and decrypt envelope
					std::vector<unsigned char> plaintext = crypto->decryptAsymmetric(ourEncryptionKeys[fingerprint], envelope);
					//remove shared key, we're done with it
					sharedKeys.erase(packet->guid);
					mux.unlock();
					//Append extra NULL so it's a string
					plaintext.push_back(0);
					Log::writeToLog(Log::INFO, "Recieved plaintext: ", (char*)plaintext.data());
				}

				default:
					break;
				}
				network->deallocatePacket(packet);
			}
		}
		catch (const OpensslException& e)
		{
			Log::writeToLog(Log::ERR, e.what());
			openssl::ERR_print_errors_fp(stderr);
			mux.unlock();
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

void LocalNoiseInterface::verifyChallenge(const Fingerprint & fingerprint, const std::vector<unsigned char>& challenge, RakNet::RakNetGUID system)
{
	//Check that we have the key
	mux.lock();
	if (ourEncryptionKeys.count(fingerprint))
	{
		std::vector<unsigned char> response = crypto->signMessage(ourEncryptionKeys[fingerprint], challenge);
		RakNet::BitStream bs;
		bs.Write((RakNet::MessageID)ID_VERIFY_CHALLENGE);
		//write out the fingerprint
		fingerprint.toBitStream(bs);
		for (unsigned int i = 0; i < response.size(); ++i)
			bs.Write(response[i]);
		network->sendBitStream(&bs, system, false);
		mux.unlock();
	}
	else
		mux.unlock();
}

void LocalNoiseInterface::sendEphemeralPublicKey(const Fingerprint& fingerprint)
{
	Log::writeToLog(Log::INFO, "Sending ephemeral key to system owning public key ", fingerprint.toString());

	mux.lock();
	RakNet::RakNetGUID system = verifiedSystems[fingerprint];
	mux.unlock();

	sendEphemeralPublicKey(system);
	
}

void LocalNoiseInterface::sendEphemeralPublicKey(RakNet::RakNetGUID system)
{
	Log::writeToLog(Log::INFO, "Sending ephemeral key to system ", system.ToString());
	RakNet::BitStream bs;
	bs.Write((RakNet::MessageID)ID_SEND_EPHEMERAL_PUBKEY);
	//Write our ephemeral key for this transfer
	mux.lock();
	std::vector<unsigned char> ourEphemeralKey = CryptoHelpers::ecPublicKeyToBytes(ourEphemeralKeys[system]);
	//and write it into bitstream
	for (unsigned int i = 0; i < ourEphemeralKey.size(); ++i)
		bs.Write(ourEphemeralKey[i]);
	//now send it out onto the network
	network->sendBitStream(&bs, system, false);
	mux.unlock();

}

void LocalNoiseInterface::sendEncryptedData(const Fingerprint & fingerprint)
{
	Log::writeToLog(Log::INFO, "Sending encrypted data to system ", fingerprint.toString());
	RakNet::BitStream bs;
	bs.Write((RakNet::MessageID)ID_SEND_ENCRYPTED_DATA);
	//see if we have a shared secret and a verified system
	fingerprint.toBitStream(bs);
	mux.lock();
	if (verifiedSystems.count(fingerprint) && sharedKeys.count(verifiedSystems[fingerprint]))
	{
		//First make an encrypted envelope
		Envelope envelope = crypto->encryptAsymmetric(&(otherEncryptionKeys[fingerprint]), outgoingData[fingerprint]);
		//and encrypt it with shared secret
		std::vector<unsigned char> pfsResult = crypto->encryptSymmetric(sharedKeys[verifiedSystems[fingerprint]], envelope.toBytes());
		//send it along
		for (unsigned int i = 0; i < pfsResult.size(); ++i)
			bs.Write(pfsResult[i]);
		network->sendBitStream(&bs, verifiedSystems[fingerprint], false);
		mux.unlock();

	}
	else
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
	Log::writeToLog(Log::INFO, "Advertising public key ", fingerprint.toString());
	RakNet::BitStream bs;
	bs.Write((RakNet::MessageID)ID_OFFER_PUBKEY);
	fingerprint.toBitStream(bs);
	mux.lock();
	network->sendBitStream(&bs, RakNet::UNASSIGNED_RAKNET_GUID, true);
	mux.unlock();
}

void LocalNoiseInterface::sendChallenge(RakNet::RakNetGUID system, const Fingerprint & fingerprint)
{
	Log::writeToLog(Log::INFO, "Challenging system ", system.ToString(), " with pubkey ", fingerprint.toString());
	//Generating random 64 byte challenge
	unsigned char * randomChallenge = new unsigned char[64];
	if (1 != openssl::RAND_bytes(randomChallenge, 64))
		throw OpensslException("Couldn't get random bytes for pubkey challenge");
	//start bitstream
	RakNet::BitStream bs;
	bs.Write((RakNet::MessageID)ID_CHALLENGE_PUBKEY);
	fingerprint.toBitStream(bs);
	//Now generate a vector out of it and make it a challenge
	std::vector<unsigned char> challenge;
	for (unsigned int i = 0; i < 64; ++i)
	{
		challenge.push_back(randomChallenge[i]);
		bs.Write(randomChallenge[i]);
	}
	//Send the challenge along
	mux.lock();
	network->sendBitStream(&bs, system, false);
	mux.unlock();

	//and set our challenge into live challenges
	liveChallenges[fingerprint] = challenge;

}

void LocalNoiseInterface::sendData(const Fingerprint & fingerprint, const std::vector<unsigned char>& data)
{
	//Start off by even checking if we have that fingerprint avaliable and a verified system to send it to
	mux.lock();
	if (!otherEncryptionKeys.count(fingerprint) && !verifiedSystems.count(fingerprint))
	{
		mux.unlock();
		return;
	}

	//Now store the data before kicking off the exchanges
	outgoingData[fingerprint] = data;

	//generate us a ephermeral key to send it along
	openssl::EVP_PKEY* newEpehemeralKey = 0;
	crypto->generateEphemeralKeypair(&newEpehemeralKey);
	//save it
	ourEphemeralKeys[verifiedSystems[fingerprint]] = newEpehemeralKey;
	//and send it along
	mux.unlock();
	sendEphemeralPublicKey(fingerprint);
}

Fingerprint LocalNoiseInterface::getFingerprint(RakNet::RakNetGUID system)
{
	mux.lock();
	for (auto it = verifiedSystems.begin(); it != verifiedSystems.end(); ++it)
	{
		if (it->second == system)
		{
			Fingerprint fingerprint = it->first;
			mux.unlock();
			return fingerprint;
		}
	}
	mux.unlock();
	return Fingerprint();
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
