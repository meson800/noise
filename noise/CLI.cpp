#include "CLI.h"
#include "Globals.h"
#include "NoiseInterface.h"
#include "Fingerprint.h"
#include "Helpers.h"
#include "Exceptions.h"

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

	//Load key from file. First see if it is unencrypted
	if (!(inter->loadKeysFromFile()))
	{
		//aww, it failed. This means that the file must be encrypted or corrupted
		std::cout << "Couldn't open key database. It's either encrypted or corrupted.\n"
			<< "If you want to skip database import, just enter an empty password at the following prompts\n"
			<< "Skipping import will result in a loss of keys!\n";
		bool done = false;
		while (!done)
		{
			std::cout << "Enter a key database password:";
			std::string password;
			std::getline(std::cin, password);
			if (password.size() == 0)
				break;
			done = inter->loadKeysFromFile(Helpers::stringToBytes(password));
		}
	}
	
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
			//try to save our keys
			std::cout << "Enter a key database password (press enter to save without encrypting the database):";
			std::string password;
			std::getline(std::cin, password);
			if (password.size() == 0)
				inter->writeKeysToFile();
			else
				inter->writeKeysToFile(Helpers::stringToBytes(password));
			mut.lock();
			running = false;
			mut.unlock();
			return;
		}
		else if (input.size() == 1 && input.c_str()[0] == 'k')
		{
			//Show key menu
			std::cout << "---Keys---\n1)Show keypairs\n2)Show public keys\n3)Create new keypair\n>";
			int choice = 0;
			std::cin >> choice;
			switch (choice)
			{
			case 0:
				break;
			case 1:
				for (unsigned int i = 0; i < inter->numOurEncryptionKeys(); ++i)
					std::cout << "Keypair " << i << ":" << inter->getOurEncryptionKeyByIndex(i).toString() << "\n";
				break;
			case 2:
				for (unsigned int i = 0; i < inter->numOtherEncryptionKeys(); ++i)
					std::cout << "Public key " << i << ":" << inter->getOtherEncryptionKeyByIndex(i).toString() << "\n";
				break;
			case 3:
			{
				//create new key
				Fingerprint fingerprint = inter->generateNewEncryptionKey();
				inter->advertiseOurPublicKey(fingerprint);
				std::cout << "Sucessefully created key " << fingerprint.toString() << "\n";
				break;
			}
			default:
				break;
			}
		}
		else if (input.size() == 1 && input.c_str()[0] == 'e')
		{
			std::cout << "---Send encrypted data---\n";
			bool bad = false;
			unsigned int ourKey, otherKey;
			try
			{
				ourKey = selectOurKey();
			}
			catch (SelectionException)
			{
				std::cout << "No keypairs to send from, generate one from the (k)ey menu\n";
				bad = true;
			}

			bool done = false;

			while (!done)
			{
				try
				{
					otherKey = selectOtherKey();
					done = true;
				}
				catch (SelectionException)
				{
					std::cout << "No public keys to select from";
				}
				if (!(inter->hasVerifiedNode(inter->getOtherEncryptionKeyByIndex(otherKey))))
				{
					std::cout << "No verified node found for public key, unable to send\n";
					bad = true;
				}
			}

			if (!bad)
			{
				std::cout << "Enter plaintext to encrypt:";
				std::string plaintext;
				std::getline(std::cin, plaintext);
				std::vector<unsigned char> plaintextBytes;
				for (unsigned int i = 0; i < plaintext.size(); ++i)
					plaintextBytes.push_back(plaintext[i]);
				inter->sendData(inter->getOurEncryptionKeyByIndex(ourKey),
					inter->getOtherEncryptionKeyByIndex(otherKey), plaintextBytes);
			}
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

unsigned int CLI::selectOurKey()
{
	bool done = false;
	unsigned int result = 0;
	while (!done)
	{
		if (inter->numOurEncryptionKeys() == 0)
			throw SelectionException("No available keypairs to select from");
		for (unsigned int i = 0; i < inter->numOurEncryptionKeys(); ++i)
			std::cout << "Keypair " << i << ":" << inter->getOurEncryptionKeyByIndex(i).toString() << "\n>";
		std::cin >> result;

		if (result >= inter->numOurEncryptionKeys())
		{
			std::cout << "Key selected is out of range, select another key\n";
		}
		else
			done = true;
	}
	std::cin.ignore(1024, '\n');
	return result;
}

unsigned int CLI::selectOtherKey()
{
	bool done = false;
	unsigned int result = 0;
	while (!done)
	{
		if (inter->numOtherEncryptionKeys() == 0)
			throw SelectionException("No available public keys to select from");
		for (unsigned int i = 0; i < inter->numOtherEncryptionKeys(); ++i)
			std::cout << "Public key " << i << ":" << inter->getOtherEncryptionKeyByIndex(i).toString() << "\n>";
		std::cin >> result;

		if (result >= inter->numOtherEncryptionKeys())
		{
			std::cout << "Key selected is out of range, select another key\n";
		}
		else
			done = true;
	}
	std::cin.ignore(1024, '\n');
	return result;
}
