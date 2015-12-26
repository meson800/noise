#include <iostream>

#include "Log.h"
#include "Network.h"

int main()
{
	Log::setLogfile("noise.log");
	Log::shouldMirrorToConsole(true);
	Log::setLogLevel(Log::L_DEBUG);
	Log::writeToLog("Starting Noise client...");

	Network network;
	network.startNode();

	std::cin.ignore();
	return 0;
}