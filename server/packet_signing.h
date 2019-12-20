#pragma once

#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

struct Signed_Packet {
	constexpr Signed_Packet() :
		socket(-1),
		ctx(NULL),
		c(0) {}
	int socket;
	HMAC_CTX* ctx;
	int c;
};

using SignedPacket = Signed_Packet;

inline void Begin(SignedPacket& pkt, int s, const Session_Key& session) {
	//HMAC_CTX_init(&pkt.ctx);
	pkt.ctx = HMAC_CTX_new();
	HMAC_Init_ex(pkt.ctx, session, SESSION_KEY_LEN, EVP_sha256(), NULL);
	pkt.c = 0; // init:0, sending:1, recving:2
	pkt.socket = s;
}

inline int Send(SignedPacket& pkt, const void* buf, int len) {
	assert(pkt.c == 1 || pkt.c == 0);
	pkt.c = 1;
	HMAC_Update(pkt.ctx, (unsigned char*)buf, len);
	return send(pkt.socket, (char*)buf, len, MSG_MORE);
}

template<typename T>
inline int Send(SignedPacket& pkt, const T& buf) {
	return Send(pkt, &buf, sizeof(T));
}

inline int Recv(SignedPacket& pkt, void* buf, int len) {
	assert(pkt.c == 2 || pkt.c == 0);
	pkt.c = 2;
	int ret = recv(pkt.socket, (char*)buf, len, 0);
	if(ret != -1) {
		HMAC_Update(pkt.ctx, (unsigned char*)buf, ret);
	}
	return ret;
}

template<typename T>
inline int Recv(SignedPacket& pkt, T& buf) {
	return Recv(pkt, &buf, sizeof(T));
}

[[nodiscard]]
inline bool End(SignedPacket& pkt) {
	unsigned int cubMD = 32;
	unsigned char hmacCalc[32];
	unsigned char hmacRecv[32];
	bool ret;
	int rd;

	HMAC_Final(pkt.ctx, hmacCalc, &cubMD);
	HMAC_CTX_free(pkt.ctx);
	pkt.ctx = NULL;

	switch(pkt.c) {
		case 1:
			ret = send(pkt.socket, (char*)hmacCalc, 32, 0) == 32;
			break;
		case 2:
			rd = recv(pkt.socket, (char*)hmacRecv, 32, 0);
			if(rd == 32) {
				ret = memcmp(hmacRecv, hmacCalc, 32) == 0;
				if(!ret) {
					fprintf(stderr, "Packet HMAC mismatch:\nReceived: ");
					for(int i = 0; i < 32; i++) {
						fprintf(stderr, "%x:", hmacRecv[i]);
					}
					fprintf(stderr, "\nExpected: ");
					for(int i = 0; i < 32; i++) {
						fprintf(stderr, "%x:", hmacCalc[i]);
					}
					fprintf(stderr, "\n");
				}
			} else {
				fprintf(stderr, "No signature was sent!\n");
			}
			break;
		default:
			assert(0);
			break;
	}

	return ret;
}

