#include <iostream>
#include <sstream>
#include <string>
#include <thread>

#include "NoiseAPI.h"
#include "NoiseInterface.h"
#include "CLI.h"


int main()
{
	NoiseInterface* inter = NoiseAPI::createNoiseInterface();
	CLI cli(inter);
	//start interface
	cli.runInterface();
	NoiseAPI::destroyNoiseInterface(inter);
	return 0;
}