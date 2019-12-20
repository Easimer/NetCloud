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

void HandleFileSize(Client& cli, Packet_File_Generic_Path* pkt) {
	int res;
	FILE* f;
	char* filename;
	const char* pktPath;

	Packet_File_Size_Result pktResult;
	Signed_Packet sp;

	pktResult.hdr = MakeHeader(CMD_SIZE, sizeof(pktResult));

	pktPath = (const char*)(pkt + 1);
	filename = new char[pkt->cubFileName + 1];
	assert(filename);
	memcpy(filename, pktPath, pkt->cubFileName);
	filename[pkt->cubFileName] = 0;
	printf("Client %ld is looking for file '%s'\n", cli.userID, filename);
	f = fopen_nc(filename, "rb", cli.userID, cli.appID);
	// TODO: Do bounds check
	if(f) {
		fseek(f, 0, SEEK_END);
		pktResult.fileLength = ftell(f);
		fclose(f);
	} else {
		pktResult.fileLength = -1;
	}

	Begin(sp, cli.socket, cli.sessionKey);
	Send(sp, pktResult);
	End(sp);

	delete[] filename;
}
