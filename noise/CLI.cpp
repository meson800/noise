#include "CLI.h"
#include "Globals.h"
#include "Network.h"

#include <iostream>
#include <sstream>
#include <string>

CLI::CLI(Network * _network) : network(_network) , shouldStop(false){}

void CLI::runInterface()
{
	//runs recursively until stopped
	while (true)
	{
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
			network->connectToNode(address, portNum);

		}
		else if (input.size() == 1 && input.c_str()[0] == 'x')
		{
			//shutdown network and close
			network->shutdownNode();
			return;
		}
	}
}

void CLI::stopInterface()
{
	mut.lock();
	shouldStop = true;
	mut.unlock();
}
