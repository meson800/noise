#include <noise/NoiseAPI.h>
#include <noise/NoiseInterface.h>
#include <noise/Fingerprint.h>
#include <noise/Helpers.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> 

#include <iostream>
#include <thread>

void read_data(int message_fd)
{
	unsigned char buf [1024];
	unsigned int readBytes = 0;
	while (readBytes = read(message_fd, buf, 1024)) 
	{
		for (unsigned int i = 0; i < readBytes; ++i)
			std::cout << buf[i];
	}
}

int main()
{
	int input_fd = open("noise_daemon_input", O_WRONLY);
	int output_fd = open("noise_daemon_output", O_RDONLY);

	if (input_fd == -1 || output_fd == -1) {
		close(input_fd);
		close(output_fd);
		return 1;
	}
	
	//do work
	std::cout << "Opened pipes\n";
	std::thread readThread(read_data, output_fd);

	std::string input_line;
	while (getline(std::cin, input_line)) {
		//split on a dash to send the message
		Fingerprint fingerprint(input_line.substr(0, input_line.find_first_of('-')));
		std::string message = input_line.substr(input_line.find_first_of('-') + 1);	
		std::vector<unsigned char> data = Helpers::stringToBytes(message);
		std::vector<unsigned char> fingerprint_size = Helpers::uintToBytes(fingerprint.data.size());
		write(input_fd, fingerprint_size.data(), fingerprint_size.size());
		write(input_fd,fingerprint.data.data(), fingerprint.data.size());
		std::vector<unsigned char> message_size = Helpers::uintToBytes(message.size());
		write(input_fd, message_size.data(), message_size.size());
		write(input_fd, data.data(), message.size());
	}
	write(input_fd, "Test", sizeof("Test"));
	std::cout << "Closing pipes and exiting\n";
	close(input_fd);
	close(output_fd);
	readThread.join();
	return 0;
}
