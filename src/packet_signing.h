#pragma once

#include <stdio.h>
#include <string.h>
#include "hmac.h"

template<typename T>
inline void SignServerPacket(T& packet, const unsigned char session[32]) {
	memset(packet.hdr.hmac, 0, 32);
	CalculateHMAC(packet.hdr.hmac, &packet.hdr, session);
}

template<typename T>
inline bool AuthenticateClientPacket(T& packet, const unsigned char session[32]) {
	bool ret;
	unsigned char original[32];

	memcpy(original, packet.hdr.hmac, 32);
	memset(packet.hdr.hmac, 0, 32);
	CalculateHMAC(packet.hdr.hmac, &packet.hdr, session);
	ret = memcmp(packet.hdr.hmac, original, 32) == 0;

	memcpy(packet.hdr.hmac, original, 32);

	return ret;
}

template<typename T>
inline bool AuthenticateClientPacket(T* packet, unsigned len, const Client& cli) {
	bool ret;
	unsigned char original[32];
	unsigned char calculated[32];

	memcpy(original, packet->hdr.hmac, 32);
	memset(packet->hdr.hmac, 0, 32);
	CalculateHMAC(calculated, cli, packet, len);
	ret = memcmp(calculated, original, 32) == 0;

	memcpy(packet->hdr.hmac, original, 32);

	return ret;
}
