#include "Message.h"

std::string Message::toString()
{
	std::string result = "Recieved message from pubkey ";
	result += from.toString();
	result += "\n";
	for (unsigned int i = 0; i < message.size(); ++i)
		result += (char)message[i];
	return result;
}
