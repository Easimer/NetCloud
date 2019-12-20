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

void HandleFileDelete(Client& cli, Packet_File_Generic_Path* pkt, int cmdOrig) {
	int res;
	FILE* f;
	char* filename;
	const char* pktPath;

	Packet_File_Delete_Result pktResult;
	Signed_Packet sp;

	pktResult.hdr = MakeHeader(cmdOrig, sizeof(pktResult));

	pktPath = (const char*)(pkt + 1);
	filename = new char[pkt->cubFileName + 1];
	assert(filename);
	memcpy(filename, pktPath, pkt->cubFileName);
	filename[pkt->cubFileName] = 0;
	printf("Client %ld is deleting file '%s'\n", cli.userID, filename);

	remove_nc(filename, cli.userID, cli.appID);
	pktResult.result = 1;

	Begin(sp, cli.socket, cli.sessionKey);
	Send(sp, pktResult);
	End(sp);

	delete[] filename;
}
