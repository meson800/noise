#include <iostream>

#include "Log.h"

int main()
{
	Log::setLogfile("noise.log");
	Log::shouldMirrorToConsole(true);
	Log::setLogLevel(Log::L_DEBUG);
	Log::writeToLog("Starting Noise client...");
	std::cin.ignore();
	return 0;
}