#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include "../noise/Log.h"
#include "Network.h"


int main()
{
	Log::setLogfile("noise.log");
	Log::clearLog();
	Log::shouldMirrorToConsole(true);
	Log::setLogLevel(Log::INFO);
	Log::writeToLog("Starting Noise client...");

	Network network;
	network.startNode();
	while (true)
	{
		RakNet::Packet* packet = network.handlePacket();
		if (packet)
			network.deallocatePacket(packet);
	}
	network.shutdownNode();
	return 0;
}