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
	const char *pktPath, *pktContents;
	Packet_File_Write_Result pktResult;
	Signed_Packet sp;

	pktResult.hdr = MakeHeader(CMD_WRITE, sizeof(pktResult));
	pktResult.result = 0;

	printf("Processing file write request from user %ld\n", cli.userID);

	pktPath = (const char*)(pkt + 1);
	pktContents = (const char*)(pktPath + pkt->cubFileName);
	filename = new char[pkt->cubFileName + 1];
	assert(filename);
	memcpy(filename, pktPath, pkt->cubFileName);
	filename[pkt->cubFileName] = 0;
	printf("Client %ld is writing file '%s'\n", cli.userID, filename);
	f = fopen_nc(filename, "wb", cli.userID, cli.appID);

	if(f) {
		pktResult.result = fwrite(pktContents, pkt->cubFileContents, 1, f) == 1;
		fclose(f);
		printf("File '%s' has been written\n", filename);
	}

	Begin(sp, cli.socket, cli.sessionKey);
	Send(sp, pktResult);
	End(sp);

	delete[] filename;
}
