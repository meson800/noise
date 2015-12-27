#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include "Log.h"
#include "Network.h"
#include "Globals.h"
#include "CLI.h"

int main()
{
	Log::setLogfile("noise.log");
	Log::clearLog();
	Log::shouldMirrorToConsole(true);
	Log::setLogLevel(Log::L_DEBUG);
	Log::writeToLog("Starting Noise client...");

	std::cout << "Enter a port number (50000):";
	std::string portNum;
	std::getline(std::cin, portNum);
	int port = SERVER_PORT;
	if (portNum.size() > 0)
	{
		std::istringstream ss(portNum);
		ss >> port;
	}

	Network network(port);
	network.startNode();

	//Init interface
	CLI cli(&network);
	//start interface
	std::thread interfaceThread(&CLI::runInterface, &cli);
	while (network.isRunning())
	{
		network.handlePacket();
	}
	//wait for interface to finish cleaning up
	interfaceThread.join();
	return 0;
}