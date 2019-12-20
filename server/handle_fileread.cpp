#include <assert.h>
#include "common.h"
#include <netcloud/protocol.h>
#include "packet_signing.h"
#include "stdio_nc.h"
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/hmac.h>

void HandleFileRead(Client& cli, Packet_File_Read* pkt) {
	int res, rd;
	FILE* f;
	char* filename;
	char buf[4096];
	Packet_File_Read_Result pktResult;
	Signed_Packet sp;
	//HMAC_CTX* ctx;
	//unsigned int cubMD = 32;

	//memset(pktResult.hdr.hmac, 0, 32);

	Begin(sp, cli.socket, cli.sessionKey);

	printf("Processing file read request from user %ld\n", cli.userID);
	const char* pktPath = (const char*)(pkt + 1);
	filename = new char[pkt->cubFileName + 1];
	assert(filename);
	memcpy(filename, pktPath, pkt->cubFileName);
	filename[pkt->cubFileName] = 0;
	printf("Client %ld is reading file '%s'\n", cli.userID, filename);

	f = fopen_nc(filename, "rb", cli.userID, cli.appID);
	pktResult.readBytes = 0;
	if(f) {
		fseek(f, 0, SEEK_END);
		pktResult.readBytes = ftell(f);
		pktResult.hdr = MakeHeader(CMD_READ, sizeof(pktResult) + pktResult.readBytes);
		Send(sp, pktResult);
		fseek(f, 0, SEEK_SET);
		rd = fread(buf, 1, 4096, f);
		while(rd > 0) {
			Send(sp, buf, rd);
			rd = fread(buf, 1, 4096, f);
		}
	} else {
		pktResult.hdr = MakeHeader(CMD_READ, sizeof(pktResult));
		pktResult.readBytes = -1;
		Send(sp, pktResult);
	}
	delete[] filename;

	if(!End(sp)) {
		cli.state = ClientState::End;
	}
}
