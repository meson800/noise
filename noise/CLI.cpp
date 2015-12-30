#include "CLI.h"
#include "Globals.h"
#include "NoiseInterface.h"
#include "Fingerprint.h"

#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <RakNetTypes.h>

namespace openssl
{
	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

CLI::CLI(NoiseInterface* _interface): inter(_interface), shouldStop(false), running(true) {}

void CLI::runInterface()
{
	mut.lock();
	running = true;
	mut.unlock();
	std::cout << "---Noise Command Line Interface---\n";

	std::cout << "Enter a port number (50000):";
	std::string portNum;
	std::getline(std::cin, portNum);
	int port = SERVER_PORT;
	if (portNum.size() > 0)
	{
		std::istringstream ss(portNum);
		ss >> port;
	}
	//start networking
	std::cout << "Starting networking...\n";
	std::thread networkThread(&NoiseInterface::startNetworking, inter,port);
	std::cout << "Network started\n";
	//runs recursively until stopped
	while (true)
	{
		std::cout << ">";
		mut.lock();
		if (shouldStop)
			return;
		mut.unlock();

		std::string input;
		std::getline(std::cin, input);
		if (input.size() == 1 && input.c_str()[0] == 'c')
		{
			std::string address;
			std::cout << "Enter system address:";
			std::getline(std::cin, address);

			std::cout << "Enter port (50000):";
			std::string port;
			std::getline(std::cin, port);
			unsigned int portNum = SERVER_PORT;
			if (port.size() > 0)
			{
				std::istringstream ssPort(port);
				ssPort >> portNum;
			}

			std::cout << "Connecting...\n";
			inter->connectToNode(address, portNum);

		}
		else if (input.size() == 1 && input.c_str()[0] == 'x')
		{
			//shutdown network and close
			inter->stopNetworking();
			networkThread.join();
			mut.lock();
			running = false;
			mut.unlock();
			return;
		}
		else if (input.size() == 1 && input.c_str()[0] == 'k')
		{
			//create new key
			Fingerprint fingerprint = inter->generateNewEncryptionKey();
			inter->advertiseOurPublicKey(fingerprint);
			std::cout << "Sucessefully created key " << fingerprint.toString() << "\n";
		}
		else if (input.size() == 1 && input.c_str()[0] == 'e')
		{
			std::cout << "Enter system GUID to send data to:";
			std::string guid;
			std::getline(std::cin, guid);
			RakNet::RakNetGUID rnGuid;
			rnGuid.FromString(guid.c_str());
			Fingerprint fingerprint = inter->getFingerprint(rnGuid);

			std::cout << "Enter plaintext to encrypt:";
			std::string plaintext;
			std::getline(std::cin, plaintext);
			std::vector<unsigned char> plaintextBytes;
			for (unsigned int i = 0; i < plaintext.size(); ++i)
				plaintextBytes.push_back(plaintext[i]);
			inter->sendData(fingerprint, plaintextBytes);
		}
	}
	mut.lock();
	running = false;
	mut.unlock();
}

bool CLI::isRunning()
{
	bool result = false;
	mut.lock();
	result = running;
	mut.unlock();
	return result;
}

void CLI::stopInterface()
{
	mut.lock();
	shouldStop = true;
	mut.unlock();
}
