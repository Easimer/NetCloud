#pragma once

#include "common.h"

void CalculateHMAC(HMAC_CTX* ctx, Packet_Header* pkt, const char* key);
void CalculateHMAC(unsigned char hmac[32], const Client& cli, const void* buf, int N);
bool CheckHMAC(HMAC_CTX* ctx, Packet_Header* pkt, const char* key);
void CreateSessionKey(unsigned char sessionKey[32], const uint8 shared[64], const char* userKey);

void CalculateHMAC(unsigned char hmac[32], const Packet_Header* pkt, const unsigned char session[32]);
