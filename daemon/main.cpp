#include <noise/NoiseAPI.h>
#include <noise/NoiseInterface.h>
#include <noise/Helpers.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> 

#include <iostream>
#include <thread>

bool stopping = false;

void send_messages(NoiseInterface * inter, int output_fd)
{
	Message incomingMessage;
	while (true)
	{
		Helpers::sleep_ms(15);
		incomingMessage = inter->getEncryptedMessage();
		if (incomingMessage.message.size() != 0)
		{
			std::cout << "Recieved a message:" << incomingMessage.toString() << "\n";
			write(output_fd, incomingMessage.message.data(), incomingMessage.message.size());
		}
		if (stopping)
			return;
	}
}
			

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
	std::thread networkingThread(&NoiseInterface::startNetworking, inter, SERVER_PORT);
	std::cout << "started successfully!\n";
	//try to load keys
	inter->loadKeysFromFile();
	if (inter->numOurEncryptionKeys() == 0) {
		inter->generateNewEncryptionKey();
	}
	std::cout << "dameon started using encryption key " << inter->getOurEncryptionKeyByIndex(0).toString() << "\n";
	//does work
	unsigned char buf [1024];
	unsigned int readBytes = 0;
	bool hasReadKey = false;
	bool hasSizedKey = false;
	unsigned int keyLength = 0;
	unsigned int messageLength = 0;
	bool hasSizedMessage = 0;
	bool hasReadMessage = 0;
	std::vector<unsigned char> accum;
	Fingerprint key;
	std::vector<unsigned char> message;


	std::thread outputThread(send_messages, inter, output_fd);
	while (readBytes = read(input_fd, buf, 1024)) 
	{
		accum.insert(accum.end(), buf, buf + readBytes);
		if (!hasSizedKey && accum.size() >= 4)
		{
			keyLength = Helpers::bytesToUINT(accum.data());	
			accum.erase(accum.begin(), accum.begin() + 4);
			std::cout << "Sized key to " << keyLength << " bytes\n";
			hasSizedKey = true;
		}
		if (hasSizedKey && !hasReadKey && accum.size() >= keyLength)
		{
			key = Fingerprint(std::vector<unsigned char>(accum.begin(), accum.begin() + keyLength));
			accum.erase(accum.begin(), accum.begin() + keyLength);
			std::cout << "Read key " << key.toString() << "\n";
			hasReadKey = true;
		}
		if (hasSizedKey && hasReadKey && !hasSizedMessage && accum.size() >= 4)
		{
			messageLength = Helpers::bytesToUINT(accum.data());
			accum.erase(accum.begin(), accum.begin() + 4);
			std::cout << "Sized message to " << messageLength << " bytes\n";
			hasSizedMessage = true;
		}
		if (hasSizedKey && hasReadKey && hasSizedMessage && !hasReadMessage && accum.size() >= messageLength)
		{
			message = std::vector<unsigned char>(accum.begin(), accum.begin() + messageLength);
			accum.erase(accum.begin(), accum.begin() + messageLength);
			std::cout << "Message to " << key.toString() << " -";
			for (unsigned int i = 0; i < message.size(); ++i)
			{
				std::cout << message[i];
			}
			std::cout << "\n";
			inter->sendData(inter->getOurEncryptionKeyByIndex(0), key, message);
			hasSizedKey = hasReadKey = hasSizedMessage = hasReadMessage = false;
		}
	}	
	std::cout << "daemon shutting down...";
	stopping = true;
	inter->writeKeysToFile();
	inter->stopNetworking();
	networkingThread.join();
	outputThread.join();
	NoiseAPI::destroyNoiseInterface(inter);
	close(input_fd);
	close(output_fd);
	unlink("noise_daemon_input");
	unlink("noise_daemon_output");
	std::cout << "shut down successfully\n";
	return 0;
} 	
	
