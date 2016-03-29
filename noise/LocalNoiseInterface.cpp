#include "LocalNoiseInterface.h"

#include "Network.h"
#include "Crypto.h"
#include "CryptoHelpers.h"
#include "Helpers.h"
#include "Exceptions.h"

#include <RakPeerInterface.h>
#include <MessageIdentifiers.h>
#include "Messages.h"
#include <BitStream.h>
#include <stdlib.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#define Sleep(a) sleep(a)
#endif
#include "Log.h"

namespace openssl
{
#include <openssl/rand.h>
#include <openssl/err.h>
}

LocalNoiseInterface::LocalNoiseInterface() : network(0), crypto(0)
{
	//we can init crypto at this point
	crypto = new Crypto();

	//and set advertise time
	lastAdvertiseTime = time(0);
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
			//see if it's time to advertise
			time_t now = time(0);
			if (now - lastAdvertiseTime > 10)
			{
				//request nodes from directory
				mux.lock();
				network->requestNodesFromDirectory();
				mux.unlock();
				//advertise our keys and request verification on other keys
				mux.lock();
				unsigned int upperBound = ourFingerprints.size();
				mux.unlock();
				for (unsigned int i = 0; i < upperBound; ++i)
				{
					mux.lock();
					Fingerprint fingerprint = ourFingerprints[i];
					mux.unlock();
					advertiseOurPublicKey(fingerprint);
				}
				//now try to verify systems that we haven't verified yet
				mux.lock();
				upperBound = otherFingerprints.size();
				mux.unlock();
				for (unsigned int i = 0; i < upperBound; ++i)
				{
					mux.lock();
					if (!verifiedSystems.count(otherFingerprints[i]))
					{
						Fingerprint fingerprint = otherFingerprints[i];
						mux.unlock();
						sendChallenge(RakNet::UNASSIGNED_RAKNET_GUID, fingerprint, true);
					}
					else
						mux.unlock();
				}
				lastAdvertiseTime = now;
			}
			if (packet == 0)
				Sleep(15);
			//Sleep if we're done with packets for the moment

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
					bsIn.IgnoreBytes(sizeof(RakNet::MessageID));
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
					otherFingerprints.push_back(fingerprint);
					otherEncryptionKeys[fingerprint] = newKey;

					//send a challenge--TEMPORARY
					sendChallenge(packet->guid, fingerprint);
					break;
				}

				case ID_CHALLENGE_PUBKEY:
				{
					RakNet::BitStream bsIn(packet->data, packet->length, false);
					bsIn.IgnoreBytes(sizeof(RakNet::MessageID));
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
					bsIn.IgnoreBytes(sizeof(RakNet::MessageID));
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
					bsIn.IgnoreBytes(sizeof(RakNet::MessageID));

					//recieve the signed fingerprint (sending fingerprint), requested fingerprint
					//, then size of signature, then signature, then ephemeral key
					Fingerprint signerFingerprint = Fingerprint(bsIn);
					Fingerprint requestedFingerprint = Fingerprint(bsIn);

					unsigned int signatureSize = 0;
					bsIn.Read(signatureSize);

					std::vector<unsigned char> recievedSignature;
					for (unsigned int i = 0; i < signatureSize; ++i)
					{
						unsigned char cur = 0;
						bsIn.Read(cur);
						recievedSignature.push_back(cur);
					}

					std::vector<unsigned char> recievedEphemeralKeyData;
					unsigned char cur = 0;
					while (bsIn.Read(cur))
						recievedEphemeralKeyData.push_back(cur);

					mux.lock();
					//verify the signature
					if (crypto->verifySignature(otherEncryptionKeys[signerFingerprint], recievedEphemeralKeyData, recievedSignature))
					{
						Log::writeToLog(Log::INFO, "Recieved good signature for ephemeral key");
					}
					else
					{
						Log::writeToLog(Log::INFO, "Recieved invalid signature for ephemeral key, discarding");
						mux.unlock();
						break;
					}
					openssl::EVP_PKEY* recievedKey = CryptoHelpers::bytesToEcPublicKey(recievedEphemeralKeyData);
					outgoingData[packet->guid].otherEphemeralKey = recievedKey;
					//now that we've read a key, let's see if we have sent ours yet

					if (outgoingData[packet->guid].ourEphemeralKey != 0)
					{
						Log::writeToLog(Log::INFO, "Deriving shared secret with system ", packet->guid.ToString());
						//yes, we've sent our key to them. Let's derive a shared secret and send our packet along :)
						SymmetricKey sharedKey;
						crypto->deriveSharedKey(outgoingData[packet->guid].ourEphemeralKey, recievedKey, sharedKey);
						outgoingData[packet->guid].sharedKey = sharedKey;
						//erase ephemeral keys, we must reset for the next packet
						//Note that the deriveSharedKey deletes the keys, so just zero this
						outgoingData[packet->guid].ourEphemeralKey = 0;
						outgoingData[packet->guid].otherEphemeralKey = 0;

						//find the fingerprint that we want for the encrypted data we want to send
						Fingerprint fingerprint = outgoingData[packet->guid].otherKey;
						mux.unlock();
						if (fingerprint.data.size() > 0)
						{
							sendEncryptedData(fingerprint);
							mux.lock();
							//Delete the outgoing data, we did it
							outgoingData.erase(packet->guid);
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
						outgoingData[packet->guid].ourKey = requestedFingerprint;
						outgoingData[packet->guid].otherKey = signerFingerprint;
						outgoingData[packet->guid].ourEphemeralKey = newEphemeralKey;
						mux.unlock();
						//we have to send before generating shared secret, as deriving destroys the keys
						sendEphemeralPublicKey(packet->guid);
						mux.lock();
						//generate shared secret 
						SymmetricKey sharedKey;
						crypto->deriveSharedKey(outgoingData[packet->guid].ourEphemeralKey, recievedKey, sharedKey);
						outgoingData[packet->guid].sharedKey = sharedKey;

						//clear ephemeral keys
						outgoingData[packet->guid].ourEphemeralKey = 0;
						outgoingData[packet->guid].otherEphemeralKey = 0;
						//and send ours along
						mux.unlock();

					}
					break;
				}

				case ID_SEND_ENCRYPTED_DATA:
				{
					Log::writeToLog(Log::INFO, "Recieved encrypted data from system ", packet->guid.ToString());
					RakNet::BitStream bsIn(packet->data, packet->length, false);
					bsIn.IgnoreBytes(sizeof(RakNet::MessageID));
					Fingerprint fingerprint = Fingerprint(bsIn);
					//read bytes in
					std::vector<unsigned char> cipherCiphertext;
					unsigned char cur = 0;
					while (bsIn.Read(cur))
						cipherCiphertext.push_back(cur);

					//decrypt it!!!
					mux.lock();
					std::vector<unsigned char> ciphertext = crypto->decryptSymmetric(outgoingData[packet->guid].sharedKey, cipherCiphertext);
					//expand into envelope
					Envelope envelope = Envelope(ciphertext);
					//and decrypt envelope
					std::vector<unsigned char> plaintext = crypto->decryptAsymmetric(ourEncryptionKeys[fingerprint], envelope);
					//save message
					Message newMessage;
					newMessage.to = fingerprint;
					newMessage.from = outgoingData[packet->guid].otherKey;
					newMessage.message = plaintext;
					incomingMessages.push_back(newMessage);
					//remove shared key, we're done with it
					outgoingData.erase(packet->guid);
					mux.unlock();
					//Append extra NULL so it's a string
					plaintext.push_back(0);
					Log::writeToLog(Log::INFO, "Recieved plaintext: ", (char*)plaintext.data());

					break;
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
	std::vector<unsigned char> ourEphemeralKey = CryptoHelpers::ecPublicKeyToBytes(outgoingData[system].ourEphemeralKey);
	std::vector<unsigned char> ourSignature = crypto->signMessage(ourEncryptionKeys[outgoingData[system].ourKey], ourEphemeralKey);

	//now send our fingerprint along, then size of signature, then our ephemeral key

	outgoingData[system].ourKey.toBitStream(bs);
	outgoingData[system].otherKey.toBitStream(bs);

	bs.Write(ourSignature.size());
	for (unsigned int i = 0; i < ourSignature.size(); ++i)
		bs.Write(ourSignature[i]);

	//sign ephemeral key with our key
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
	if (verifiedSystems.count(fingerprint) && outgoingData[verifiedSystems[fingerprint]].sharedKey.key.size() > 0)
	{
		//First make an encrypted envelope
		Envelope envelope = crypto->encryptAsymmetric(&(otherEncryptionKeys[fingerprint]), outgoingData[verifiedSystems[fingerprint]].data);
		//and encrypt it with shared secret
		std::vector<unsigned char> pfsResult = crypto->encryptSymmetric(outgoingData[verifiedSystems[fingerprint]].sharedKey, envelope.toBytes());
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

void LocalNoiseInterface::sendChallenge(RakNet::RakNetGUID system, const Fingerprint & fingerprint, bool broadcast)
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
	network->sendBitStream(&bs, system, broadcast);
	mux.unlock();

	//and set our challenge into live challenges
	liveChallenges[fingerprint] = challenge;

}

void LocalNoiseInterface::sendData(const Fingerprint& ourFingerprint, const Fingerprint& otherFingerprint, const std::vector<unsigned char>& data)
{
	//Start off by even checking if we have that fingerprint avaliable and a verified system to send it to
	mux.lock();
	if (!otherEncryptionKeys.count(otherFingerprint) && !verifiedSystems.count(otherFingerprint))
	{
		mux.unlock();
		return;
	}


	outgoingData[verifiedSystems[otherFingerprint]].ourKey = ourFingerprint;
	outgoingData[verifiedSystems[otherFingerprint]].otherKey = otherFingerprint;
	outgoingData[verifiedSystems[otherFingerprint]].otherSystem = verifiedSystems[otherFingerprint];
	//Now store the data before kicking off the exchanges
	outgoingData[verifiedSystems[otherFingerprint]].data = data;

	//generate us a ephermeral key to send it along
	openssl::EVP_PKEY* newEpehemeralKey = 0;
	crypto->generateEphemeralKeypair(&newEpehemeralKey);
	//save it
	outgoingData[verifiedSystems[otherFingerprint]].ourEphemeralKey = newEpehemeralKey;
	//and send it along
	mux.unlock();
	sendEphemeralPublicKey(otherFingerprint);
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
		ourFingerprints.push_back(fingerprint);
		ourEncryptionKeys[fingerprint] = newKey;
		mux.unlock();
		return fingerprint;
	}
	//if we get to this point, crypto wasn't enabled
	mux.unlock();
	throw InterfaceException("Crypto not initalized");
}

Fingerprint LocalNoiseInterface::getOurEncryptionKeyByIndex(unsigned int index)
{
	mux.lock();
	if (index >= ourEncryptionKeys.size())
	{
		mux.unlock();
		throw std::runtime_error("Encryption key index out of range");
	}
	Fingerprint fingerprint = ourFingerprints[index];
	mux.unlock();
	return fingerprint;
}

unsigned int LocalNoiseInterface::numOtherEncryptionKeys()
{
	unsigned int result = 0;
	mux.lock();
	result = otherEncryptionKeys.size();
	mux.unlock();
	return result;
}

Fingerprint LocalNoiseInterface::getOtherEncryptionKeyByIndex(unsigned int index)
{
	mux.lock();
	if (index >= otherEncryptionKeys.size())
	{
		mux.unlock();
		throw std::runtime_error("Other encryption key index out of range");
	}
	Fingerprint fingerprint = otherFingerprints[index];
	mux.unlock();
	return fingerprint;
}

bool LocalNoiseInterface::hasVerifiedNode(const Fingerprint & fingerprint)
{
	bool result = false;
	mux.lock();
	if (verifiedSystems.count(fingerprint))
		result = true;
	mux.unlock();
	
	return result;
}

Message LocalNoiseInterface::getEncryptedMessage()
{
	if (incomingMessages.size() != 0)
	{
		Message message = incomingMessages[0];
		incomingMessages.erase(incomingMessages.begin());
		return message;
	}
	return Message();
}

bool LocalNoiseInterface::setUserData(const Fingerprint & fingerprint, const std::vector<unsigned char>& data)
{
	if (!ourEncryptionKeys.count(fingerprint) && !otherEncryptionKeys.count(fingerprint))
	{
		//we don't have an fingerprint for that key, don't attach data
		return false;
	}
	userdata[fingerprint] = data;
	return true;
}

std::vector<unsigned char> LocalNoiseInterface::getUserData(const Fingerprint & fingerprint)
{
	if (userdata.count(fingerprint))
		return userdata[fingerprint];
	return fingerprint.data;
}

unsigned int LocalNoiseInterface::numOurEncryptionKeys()
{
	unsigned int result = 0;
	mux.lock();
	result = ourEncryptionKeys.size();
	mux.unlock();
	return result;
}


//Keypair database format
//All key database files start with the following 8 "magic" bytes
//0xC0 0xC1 0xC2 0xC3 0xC4 0xC5 0xC6 0xC7
//After that, we have an unsigned int, which is the number of keypairs (public and private key)
//Then for each keypair, we get an unsigned int size of public key, then unsigned int of private key
//After we have done all the keypairs, write the number of other public keys, 
//then the rest of the public keys are listed, with a unsigned int for size
bool LocalNoiseInterface::writeKeysToFile(std::vector<unsigned char> password)
{
	mux.lock();
	//Generate a random salt
	unsigned char* tempSalt = new unsigned char[8];
	if (1 != openssl::RAND_bytes(tempSalt, 8))
		throw OpensslException("Couldn't generate a random salt");
	std::vector<unsigned char> salt = std::vector<unsigned char>(tempSalt, tempSalt + 8);
	delete[](tempSalt);

	std::vector<unsigned char> seralizedKeys = keysToBytes();
	//now encrypt it
	SymmetricKey key = crypto->deriveKeyFromPassword(salt, password);
	Log::writeToLog(Log::L_DEBUG, "Got salt ", Fingerprint(salt, true).toString(),
		" and key ", Fingerprint(key.key, true).toString(), " and iv ", Fingerprint(key.iv, true).toString());

	std::vector<unsigned char> ciphertext = crypto->encryptSymmetric(key, seralizedKeys);

	std::vector<unsigned char> result;
	Helpers::insertVector(result, salt);
	Helpers::insertVector(result, ciphertext);

	//write it out
	std::ofstream file;
        file.open("noise_keys.db", 'w');
	for (unsigned int i = 0; i < result.size(); ++i)
		file << result[i];
	file.close();

	mux.unlock();
	return true;
}

bool LocalNoiseInterface::writeKeysToFile()
{
	mux.lock();
	//Simply write keys out without encryption :(
	std::ofstream file;
        file.open("noise_keys.db",  'w');
	std::vector<unsigned char> seralizedKeys = keysToBytes();
	for (unsigned int i = 0; i < seralizedKeys.size(); ++i)
		file << seralizedKeys[i];
	file.close();
	mux.unlock();
	return false;
}

bool LocalNoiseInterface::loadKeysFromFile(std::vector<unsigned char> password)
{
	mux.lock();
	//Open the file, and get the salt
	std::ifstream file;
        file.open("noise_keys.db", 'b');
	if (!file.is_open())
	{
		mux.unlock();
		return true;
	}

	std::vector<unsigned char> salt;
	for (unsigned int i = 0; i < 8; ++i)
	{
		char cur = 0;
		file.get(cur);
		salt.push_back((unsigned char)cur);
	}

	//read rest of file in
	std::vector<unsigned char> bytes;
	while (!file.eof())
	{
		char cur = 0;
		file.get(cur);
		bytes.push_back((unsigned char)cur);
	}
	file.close();
	//Ugh, this method leaves us with a trailing NULL
	//Clean it up
	bytes.erase(bytes.end() - 1);

	//derive key
	SymmetricKey key = crypto->deriveKeyFromPassword(salt, password);
	Log::writeToLog(Log::L_DEBUG, "Got salt ", Fingerprint(salt, true).toString(),
		" and key ", Fingerprint(key.key, true).toString(), " and iv ", Fingerprint(key.iv, true).toString());
	//and try to decrypt
	try
	{
		std::vector<unsigned char> plaintext = crypto->decryptSymmetric(key, bytes);
		//Turn it into keys
		bool result = bytesToKeys(plaintext);
		mux.unlock();
		return result;
	}
	catch (const OpensslException& e)
	{
		Log::writeToLog(Log::ERR, e.what());
		openssl::ERR_print_errors_fp(stderr);
		mux.unlock();
		return false;
	}
	mux.unlock();
	return false;

}

bool LocalNoiseInterface::loadKeysFromFile()
{
	mux.lock();
	//Simply read keys in without encryption :(
	std::ifstream file;
        file.open("noise_keys.db", 'b');
	if (!file.is_open())
	{
		mux.unlock();
		return true;
	}
	std::vector<unsigned char> bytes;
	while (!file.eof())
	{
		char cur = 0;
		file.get(cur);
		bytes.push_back((unsigned char)cur);
	}
	file.close();
	bool result = bytesToKeys(bytes);
	mux.unlock();
	return result;
}

std::vector<unsigned char> LocalNoiseInterface::keysToBytes()
{
	std::vector<unsigned char> bytes = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7 };
	//First write number of keypairs
	Helpers::uintToBytes(ourEncryptionKeys.size(), bytes);
	//and write key into it
	for (unsigned int i = 0; i < ourEncryptionKeys.size(); ++i)
	{
		//insert user data
		if (userdata.count(ourFingerprints[i]))
		{
			Helpers::uintToBytes(userdata[ourFingerprints[i]].size(), bytes);
			Helpers::insertVector(bytes, userdata[ourFingerprints[i]]);
		}
		else
		{
			Helpers::uintToBytes(0, bytes);
		}
		std::vector<unsigned char> pubKey = CryptoHelpers::oslPublicKeyToBytes(ourEncryptionKeys[ourFingerprints[i]]);
		std::vector<unsigned char> privKey = CryptoHelpers::oslPrivateKeyToBytes(ourEncryptionKeys[ourFingerprints[i]]);
		Helpers::uintToBytes(pubKey.size(), bytes);
		Helpers::insertVector(bytes, pubKey);
		Helpers::uintToBytes(privKey.size(), bytes);
		Helpers::insertVector(bytes, privKey);
		Log::writeToLog(Log::INFO, "Seralized keypair ", ourFingerprints[i].toString());
		Log::writeToLog(Log::L_DEBUG, "Public keypair fingerprint:", Fingerprint(pubKey, true).toString(),
			" Private keypair fingerprint:", Fingerprint(privKey, true).toString());
	}
	//Now write public keys
	Helpers::uintToBytes(otherEncryptionKeys.size(), bytes);
	for (unsigned int i = 0; i < otherEncryptionKeys.size(); ++i)
	{
		if (userdata.count(otherFingerprints[i]))
		{
			Helpers::uintToBytes(userdata[otherFingerprints[i]].size(), bytes);
			Helpers::insertVector(bytes, userdata[otherFingerprints[i]]);
		}
		else
		{
			Helpers::uintToBytes(0, bytes);
		}
		std::vector<unsigned char> pubKey = CryptoHelpers::oslPublicKeyToBytes(otherEncryptionKeys[otherFingerprints[i]]);
		Helpers::uintToBytes(pubKey.size(), bytes);
		Helpers::insertVector(bytes, pubKey);
		Log::writeToLog(Log::INFO, "Seralized public key ", otherFingerprints[i].toString());
	}
	return bytes;
}

bool LocalNoiseInterface::bytesToKeys(const std::vector<unsigned char>& bytes)
{
	//check that the first 8 bytes are our magic keys
	if (bytes[0] != 0xC0 || bytes[1] != 0xC1 || bytes[2] != 0xC2 || bytes[3] != 0xC3 ||
		bytes[4] != 0xC4 || bytes[5] != 0xC5 || bytes[6] != 0xC6 || bytes[7] != 0xC7)
		return false;

	//Okay, our magic bytes are good. Continue deseralization
	unsigned int idx = 8;
	unsigned int keypairs = Helpers::bytesToUINT(bytes.data() + idx);
	idx += 4;
	for (unsigned int i = 0; i < keypairs; ++i)
	{
		//extract userdata
		unsigned int userdataLength = Helpers::bytesToUINT(bytes.data() + idx);
		idx += 4;
		std::vector<unsigned char> newUserdata;
		if (userdataLength > 0)
		{
			newUserdata = std::vector<unsigned char>(bytes.data() + idx, bytes.data() + idx + userdataLength);
			idx += userdataLength;
		}

		//extract public then private key
		unsigned int pubKeyLength = Helpers::bytesToUINT(bytes.data() + idx);
		idx += 4;
		std::vector<unsigned char> pubKey = std::vector<unsigned char>(bytes.data() + idx, bytes.data() + idx + pubKeyLength);
		idx += pubKeyLength;
		unsigned int privKeyLength = Helpers::bytesToUINT(bytes.data() + idx);
		idx += 4;
		std::vector<unsigned char> privKey = std::vector<unsigned char>(bytes.data() + idx, bytes.data() + idx + privKeyLength);
		idx += privKeyLength;
		Log::writeToLog(Log::L_DEBUG, "Read pubkey fingerprint:", Fingerprint(pubKey, true).toString(),
			" and privkey fingerprint:", Fingerprint(privKey, true).toString());
		//get key
		try
		{
			openssl::EVP_PKEY* newKeypair = CryptoHelpers::bytesToOslKeypair(privKey, pubKey);

			//insert it into our keymap
			Fingerprint fingerprint = Fingerprint(newKeypair);
			Log::writeToLog(Log::INFO, "Read keypair ", fingerprint.toString(), " from database");
			ourEncryptionKeys[fingerprint] = newKeypair;
			ourFingerprints.push_back(fingerprint);

			if (newUserdata.size() > 0)
				userdata[fingerprint] = newUserdata;
		}
		catch (const OpensslException& e)
		{
			Log::writeToLog(Log::ERR, e.what());
			openssl::ERR_print_errors_fp(stderr);
			return false;
		}
	}

	unsigned int otherKeys = Helpers::bytesToUINT(bytes.data() + idx);
	idx += 4;
	for (unsigned int i = 0; i < otherKeys; ++i)
	{
		//extract userdata
		unsigned int userdataLength = Helpers::bytesToUINT(bytes.data() + idx);
		idx += 4;
		std::vector<unsigned char> newUserdata;
		if (userdataLength > 0)
		{
			newUserdata = std::vector<unsigned char>(bytes.data() + idx, bytes.data() + idx + userdataLength);
			idx += userdataLength;
		}

		unsigned int pubKeyLength = Helpers::bytesToUINT(bytes.data() + idx);
		idx += 4;
		std::vector<unsigned char> pubKey = std::vector<unsigned char>(bytes.data() + idx, bytes.data() + idx + pubKeyLength);
		idx += pubKeyLength;

		//get key
		openssl::EVP_PKEY* newKey = CryptoHelpers::bytesToOslPublicKey(pubKey);
		Fingerprint fingerprint = Fingerprint(newKey);
		Log::writeToLog(Log::INFO, "Read public key ", fingerprint.toString(), " from database");
		otherEncryptionKeys[fingerprint] = newKey;
		otherFingerprints.push_back(fingerprint);

		if (newUserdata.size() > 0)
			userdata[fingerprint] = newUserdata;
	}
	return true;
}
