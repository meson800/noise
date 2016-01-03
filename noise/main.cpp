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
	Log::setLogLevel(Log::INFO);
	Log::writeToLog("Starting Noise client...");


	LocalNoiseInterface inter;
	//Init interface
	CLI cli(&inter);
	//start interface
	cli.runInterface();
	return 0;
}