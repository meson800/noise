#include "CLI.h"
#include "Globals.h"
#include "NoiseInterface.h"
#include "Fingerprint.h"

#include <iostream>
#include <sstream>
#include <string>

namespace openssl
{
	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

CLI::CLI(NoiseInterface* _interface): interface(_interface), shouldStop(false), running(true) {}

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
	interface->startNetworking(port);
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
			interface->connectToNode(address, portNum);

		}
		else if (input.size() == 1 && input.c_str()[0] == 'x')
		{
			//shutdown network and close
			interface->stopNetworking();
			mut.lock();
			running = false;
			mut.unlock();
			return;
		}
		else if (input.size() == 1 && input.c_str()[0] == 'k')
		{
			//create new key
			Fingerprint fingerprint = interface->generateNewEncryptionKey();
			std::cout << "Sucessefully created key " << fingerprint.toString() << "\n";
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
