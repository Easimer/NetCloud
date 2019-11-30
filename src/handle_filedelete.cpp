#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#include "protocol.h"
#include "stdio_nc.h"
#include "packet_signing.h"

void HandleFileDelete(Client& cli, Packet_File_Generic_Path* pkt, int cmdOrig) {
	int res;
	FILE* f;
	char* filename;
	Packet_File_Delete_Result pktResult;
	pktResult.hdr.len = sizeof(pktResult);
	pktResult.hdr.cmd = cmdOrig;
	printf("Processing file delete request from user %ld\n", cli.userID);
	if(AuthenticateClientPacket(pkt, pkt->hdr.len, cli)) {
		const char* pktPath = (const char*)(pkt + 1);
		filename = new char[pkt->cubFileName + 1];
		assert(filename);
		memcpy(filename, pktPath, pkt->cubFileName);
		filename[pkt->cubFileName] = 0;
		printf("Client %ld is deleting file '%s'\n", filename);

		remove_nc(filename, cli.userID, cli.appID);
		pktResult.result = 1;

		delete[] filename;
	} else {
		pktResult.result = 0;
		printf("Failed to auth delete request\n");
	}

	printf("Sending delete request result\n");
	SignServerPacket(pktResult, cli.sessionKey);
	res = send(cli.socket, &pktResult, sizeof(pktResult), 0);
	assert(res == sizeof(pktResult));
}
