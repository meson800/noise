#include <noise/NoiseAPI.h>
#include <noise/NoiseInterface.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> 

#include <iostream>

int main()
{
	//create named pipe
	if (mkfifo("noise_daemon_input", S_IRUSR | S_IWUSR) != 0) {
		std::cout << "Couldn't create input pipe, exiting\n";
		return 1;
	}
	if (mkfifo("noise_daemon_output", S_IRUSR | S_IWUSR) != 0) {
		std::cout << "Couldn't create output pipe, exiting\n";
		unlink("noise_daemon_input");
		return 1;
	}
	//we need to read input from whatever opens our pipes, and write output
	//so open it that way
	std::cout << "Created named pipes, opening...\n";
	int input_fd = open("noise_daemon_input", O_RDONLY);
	std::cout << "Opened input pipe\n";
	int output_fd = open("noise_daemon_output", O_WRONLY);
	std::cout << "Opened output pipe\n";

	if (input_fd == -1 || output_fd == -1) {
		std::cout << "Pipes failed to open correctly, exiting\n";
		close(input_fd);
		close(output_fd);
		unlink("noise_daemon_input");
		unlink("noise_daemon_output");
		return 1;
	}
	std::cout << "Pipes opened correctly, starting noise...";
	//now that we have our file descriptors opened up, let's spin up Noise
	NoiseInterface * inter = NoiseAPI::createNoiseInterface();
	//inter->startNetworking(50000);
	std::cout << "started successfully!\n";
	//try to load keys
	inter->loadKeysFromFile();
	if (inter->numOurEncryptionKeys() == 0) {
		inter->generateNewEncryptionKey();
	}
	std::cout << "dameon started using encryption key " << inter->getOurEncryptionKeyByIndex(0).toString() << "\n";
	//does work
	std::cout << "daemon shutting down...";
	inter->writeKeysToFile();
	inter->stopNetworking();
	NoiseAPI::destroyNoiseInterface(inter);
	close(input_fd);
	close(output_fd);
	unlink("noise_daemon_input");
	unlink("noise_daemon_output");
	std::cout << "shut down successfully\n";
	return 0;
} 	
	
