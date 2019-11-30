#include <assert.h>
#include "common.h"
#include "protocol.h"
#include "packet_signing.h"
#include "stdio_nc.h"
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/hmac.h>

void HandleFileRead(Client& cli, Packet_File_Read* pkt) {
	int res;
	FILE* f;
	char* filename;
	char* bufContents = NULL;
	Packet_File_Read_Result pktResult;
	HMAC_CTX* ctx;
	unsigned int cubMD = 32;

	memset(pktResult.hdr.hmac, 0, 32);

	printf("Processing file read request from user %ld\n", cli.userID);
	if(AuthenticateClientPacket(pkt, pkt->hdr.len, cli)) {
		const char* pktPath = (const char*)(pkt + 1);
		bufContents = new char[pkt->maxReadBytes];
		filename = new char[pkt->cubFileName + 1];
		assert(filename);
		memcpy(filename, pktPath, pkt->cubFileName);
		filename[pkt->cubFileName] = 0;
		printf("Client %ld is reading file '%s'\n", cli.userID, filename);
		f = fopen_nc(filename, "rb", cli.userID, cli.appID);
		// TODO: Do bounds check
		if(f) {
			pktResult.readBytes = fread(bufContents, 1, pkt->maxReadBytes, f);
			fclose(f);
			printf("File '%s' has been read\n", filename);

			pktResult.hdr.cmd = CMD_READ;
			pktResult.hdr.len = sizeof(pktResult) + pktResult.readBytes;
		} else {
			printf("Failed to open file\n");
			delete[] bufContents;
		}
		delete[] filename;
	} else {
		pktResult.hdr.cmd = CMD_READ;
		pktResult.hdr.len = sizeof(pktResult);
		pktResult.readBytes = -1;
		printf("Failed to auth read request\n");
	}

	ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, cli.sessionKey, 32, EVP_sha256(), NULL);
	HMAC_Update(ctx, (unsigned char*)&pktResult, sizeof(pktResult));

	if(bufContents) {
		HMAC_Update(ctx, (unsigned char*)bufContents, pktResult.readBytes);
		HMAC_Final(ctx, pktResult.hdr.hmac, &cubMD);
		res  = send(cli.socket, &pktResult, sizeof(pktResult), MSG_MORE);
		res += send(cli.socket, bufContents, pktResult.readBytes, 0);
		assert(res == sizeof(pktResult) + pktResult.readBytes);
	} else {
		HMAC_Final(ctx, pktResult.hdr.hmac, &cubMD);
		send(cli.socket, &pktResult, sizeof(pktResult), 0);
		assert(res == sizeof(pktResult));
	}

	HMAC_CTX_free(ctx);
}
