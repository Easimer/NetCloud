#include <string.h>
#include <assert.h>
#include "common.h"

void CalculateHMAC(HMAC_CTX* ctx, Packet_Header* pkt, const char* key) {
	unsigned int md_len = 32;
	assert(pkt && key);
	HMAC_CTX_reset(ctx);
	memset(pkt->hmac, 0, 32);
	HMAC_Init_ex(ctx, key, strlen(key), EVP_sha256(), NULL);
	HMAC_Update(ctx, (unsigned char*)pkt, pkt->len);
	HMAC_Final(ctx, pkt->hmac, &md_len);
	printf("Calculated HMAC:\n");
	for(int i = 0; i < 32; i++) {
		printf("%x", pkt->hmac[i]);
	}
	printf("\n");
}

void CalculateHMAC(unsigned char hmac[32], const Client& cli, const void* buf, int N) {
	unsigned int cubMD = 32;
	HMAC(EVP_sha256(), cli.sessionKey, 32, (unsigned char*)buf, N, hmac, &cubMD);
}

bool CheckHMAC(HMAC_CTX* ctx, Packet_Header* pkt, const char* key) {
	bool ret = false;

	unsigned char hmacOrig[32];
	memcpy(hmacOrig, pkt->hmac, 32);

	printf("Original HMAC:\n");
	for(int i = 0; i < 32; i++) {
		printf("%x", pkt->hmac[i]);
	}
	printf("\n");

	CalculateHMAC(ctx, pkt, key);

	ret = memcmp(hmacOrig, pkt->hmac, 32) == 0;

	return ret;
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

