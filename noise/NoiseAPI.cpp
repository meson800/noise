#include "NoiseAPI.h"
#include "Log.h"
#include "LocalNoiseInterface.h"
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
		return inter;
	}
	NoiseInterface * createNoiseInterface()
	{
		return createNoiseInterface(50000);
	}
	void destroyNoiseInterface(NoiseInterface * inter)
	{
		delete inter;
	}
}


