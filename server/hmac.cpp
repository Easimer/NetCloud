#include <string.h>
#include <assert.h>
#include "common.h"

void CalculateHMAC(unsigned char hmac[32], const Client& cli, const void* buf, int N) {
	unsigned int cubMD = 32;
	HMAC(EVP_sha256(), cli.sessionKey, 32, (unsigned char*)buf, N, hmac, &cubMD);
}

void CreateSessionKey(unsigned char sessionKey[32], const uint8 shared[64], const char* userKey) {
	unsigned int cubMD = 32;
	assert(sessionKey && shared && userKey);

	HMAC(EVP_sha256(), userKey, strlen(userKey), shared, 64, sessionKey, &cubMD);
}

void CalculateHMAC(unsigned char hmac[32], const Packet_Header* pkt, const unsigned char session[32]) {
	unsigned int cubMD = 32;
	assert(hmac && pkt && session);

	HMAC(EVP_sha256(), session, 32, (unsigned char*)pkt, pkt->len, hmac, &cubMD);
}

