#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netcloud/protocol.h>
#include "common.h"
#include "stdio_nc.h"
#include "packet_signing.h"

void HandleFileWrite(Client& cli, Packet_File_Write* pkt) {
	int res;
	FILE* f;
	char* filename;
	Packet_File_Write_Result pktResult;
	printf("Processing file write request from user %ld\n", cli.userID);
	if(AuthenticateClientPacket(pkt, pkt->hdr.len, cli)) {
		const char* pktPath = (const char*)(pkt + 1);
		const char* pktContents = (const char*)(pktPath + pkt->cubFileName);
		filename = new char[pkt->cubFileName + 1];
		assert(filename);
		memcpy(filename, pktPath, pkt->cubFileName);
		filename[pkt->cubFileName] = 0;
		printf("Client %ld is writing file '%s'\n", cli.userID, filename);
		f = fopen_nc(filename, "wb", cli.userID, cli.appID);
		// TODO: Do bounds check
		if(f) {
			pktResult.result = fwrite(pktContents, pkt->cubFileContents, 1, f);
			fflush(f);
			fclose(f);
			printf("File '%s' has been written\n", filename);

			pktResult.hdr.cmd = CMD_WRITE;
			pktResult.hdr.len = sizeof(pktResult);
		}
		delete[] filename;
	} else {
		pktResult.hdr.cmd = CMD_WRITE;
		pktResult.hdr.len = sizeof(pktResult);
		pktResult.result = 0;
		printf("Failed to auth write request\n");
	}

	printf("Sending write request result\n");
	SignServerPacket(pktResult, cli.sessionKey);
	res = send(cli.socket, &pktResult, sizeof(pktResult), 0);
	assert(res == sizeof(pktResult));
}

