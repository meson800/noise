#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include "Log.h"
#include "Network.h"
#include "Globals.h"
#include "CLI.h"
#include "Crypto.h"

#include "LocalNoiseInterface.h"

int main()
{
	Log::setLogfile("noise.log");
	Log::clearLog();
	Log::shouldMirrorToConsole(true);
	Log::setLogLevel(Log::L_DEBUG);
	Log::writeToLog("Starting Noise client...");


	LocalNoiseInterface inter;
	//Init interface
	CLI cli(&inter);
	//start interface
	std::thread interfaceThread(&CLI::runInterface, &cli);
	while (cli.isRunning())
	{
		inter.handlePacket();
	}
	//wait for interface to finish cleaning up
	interfaceThread.join();
	return 0;
}