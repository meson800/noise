#pragma once

#include <MessageIdentifiers.h>

enum NoiseMessages
{
	ID_OFFER_PUBKEY = ID_USER_PACKET_ENUM + 1,
	ID_REQUEST_PUBKEY,
	ID_SEND_PUBKEY,
	ID_CHALLENGE_PUBKEY,
	ID_VERIFY_CHALLENGE,
	ID_SEND_EPHEMERAL_PUBKEY,
	ID_SEND_ENCRYPTED_DATA

};