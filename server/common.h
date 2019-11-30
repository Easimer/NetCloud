#pragma once

#include <netcloud/protocol.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>

using Session_Key = unsigned char[32];

enum class ClientState {
	Start, // Client haven't sent the login packet yet
	SentLogin, // Client sent the login packet
	WaitingForAuth, // Waiting for authentication
	Operation, // Normal operation mode
	Error, // Client failed to authenticate itself
	End // Client is logging out/has logged out
};

struct Client {
	int socket;
	uint64_t userID, appID;
	const char* pchKey;
	Session_Key sessionKey;
	ClientState state;
	HMAC_CTX* hmacCtx;
};
