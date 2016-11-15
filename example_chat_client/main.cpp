#include <noise/NoiseAPI.h>
#include <noise/NoiseInterface.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> 

#include <iostream>

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
	write(input_fd, "Test", sizeof("Test"));
	std::cout << "Closing pipes and exiting\n";
	close(input_fd);
	close(output_fd);
	return 0;
}
