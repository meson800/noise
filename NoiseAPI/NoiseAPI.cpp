#include "NoiseAPI.h"
#include "..\noise\Log.h"
#include "..\noise\LocalNoiseInterface.h"
namespace NoiseAPI
{
	NoiseInterface * createNoiseInterface(int portnum)
	{
		Log::setLogfile("noise.log");
		Log::clearLog();
		Log::shouldMirrorToConsole(false);
		Log::setLogLevel(Log::INFO);
		Log::writeToLog("Starting Noise client...");

		NoiseInterface* inter = new LocalNoiseInterface();
		inter->startNetworking(portnum);
		return inter;
	}
	NoiseInterface * createNoiseInterface()
	{
		return createNoiseInterface(50000);
	}
	void destroyNoiseInterface(NoiseInterface * inter)
	{
		inter->stopNetworking();
		delete inter;
	}
}


