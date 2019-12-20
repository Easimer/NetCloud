#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netcloud/protocol.h>

#include "common.h"
#include "hmac.h"
#include "stdio_nc.h"

#include "handlers.h"
#include "packet_signing.h"
#include "user_auth.h"
#include "db.h"

static bool isShutdown;

static bool WaitForLoginPacket(Client& cli) {
	int res;
	Packet_Login pktLogin;
	assert(cli.state == ClientState::Start);

	res = recv(cli.socket, &pktLogin, sizeof(pktLogin), 0);

	if(res == sizeof(pktLogin)) {
		cli.state = ClientState::SentLogin;
		cli.userID = pktLogin.userID;
		cli.appID = pktLogin.appID;
		printf("Client has sent login packet, userID=%llu\n", cli.userID);

		// Don't check HMAC yet

		return pktLogin.hdr.ver == NETCLOUD_PROTOCOL_VERSION;
	} else {
		return false;
	}
}

#define BEGIN_PACKET(pkt) Begin(pkt, cli.socket, cli.sessionKey)

static void SendAuthResult(Client& cli, bool res) {
	//Packet_Auth_Result pkt;
	//pkt.hdr.cmd = CMD_AUTHRES;
	//pkt.hdr.len = sizeof(pkt);
	//pkt.result = res ? 0x01 : 0x00;
	//SignServerPacket(pkt, cli.sessionKey);
	//send(cli.socket, &pkt, sizeof(pkt), 0);
	SignedPacket pkt;
	Packet_Auth_Result pktAR;

	pktAR.hdr = MakeHeader(CMD_AUTHRES, sizeof(pktAR));
	pktAR.result = res ? 0x01 : 0x00;

	BEGIN_PACKET(pkt);
	Send(pkt, pktAR);
	End(pkt);
}

static void AuthenticateClient(Client& cli) {
	int res;
	bool ok;
	unsigned char challengeExpected[32];
	Packet_Auth_Challenge pktC;
	Packet_Auth_Answer pktA;
	SignedPacket pkt;

	// Initialize auth challenge packet
	//pktC.hdr.cmd = CMD_AUTH;
	//pktC.hdr.len = sizeof(pktC);
	pktC.hdr = MakeHeader(CMD_AUTH, sizeof(pktC));
	//memset(pktC.hdr.hmac, 0, 32);
	res = RAND_bytes(pktC.shared, 64);
	assert(res != -1);
	res = RAND_bytes(pktC.challenge, 32);
	assert(res != -1);
	//CreateSessionKey(cli.sessionKey, pktC.shared, cli.pchKey);
	CreateSessionKeyForUser(cli.sessionKey, cli.userID, pktC.shared);
	//SignServerPacket(pktC, cli.sessionKey);
	CalculateHMAC(challengeExpected, cli, pktC.challenge, 32);

	Begin(pkt, cli.socket, cli.sessionKey);
	Send(pkt, pktC);
	End(pkt);
	//send(cli.socket, &pktC, sizeof(pktC), 0);

	printf("Sent challenge to user %llu\n", cli.userID);

	Begin(pkt, cli.socket, cli.sessionKey);
	//res = recv(cli.socket, &pktA, sizeof(pktA), 0);
	res = Recv(pkt, pktA);
	//assert(res == sizeof(pktA));
	//assert(pktA.hdr.len == sizeof(pktA));
	ok = End(pkt);

	printf("Received answer packet from user %llu\n", cli.userID);

	if(res == sizeof(pktA) && pktA.hdr.len == sizeof(pktA) && ok) {
		if(memcmp(pktA.answer, challengeExpected, 32) == 0) {
			printf("User %llu is now authenticated\n", cli.userID);
			cli.state = ClientState::Operation;
			SendAuthResult(cli, true);
		} else {
			printf("User %llu has sent answer with bad challenge HMAC\n", cli.userID);
			cli.state = ClientState::End;
			SendAuthResult(cli, false);
		}
	} else {
		printf("User %llu has sent answer with bad packet HMAC\n", cli.userID);
		cli.state = ClientState::End;
		SendAuthResult(cli, false);
	}
}

static void ReceiveClientCommand(Client& cli) {
	Packet_Header hdr;
	SignedPacket pkt;
	char* bufPktData = NULL;
	ssize_t res;
	size_t cubRecvLeft;
	char* cur;

	BEGIN_PACKET(pkt);

	//res = recv(cli.socket, &hdr, sizeof(hdr), 0);
	res = Recv(pkt, hdr);
	if(res != -1) {
		assert(res == sizeof(hdr));

		bufPktData = new char[hdr.len];
		memcpy(bufPktData, &hdr, sizeof(hdr));

		cubRecvLeft = hdr.len - sizeof(hdr);
		cur = bufPktData + sizeof(hdr);

		//printf("Receiving data from client %ld\n", cli.userID);

		while(cubRecvLeft > 0) {
			//res = recv(cli.socket, cur, cubRecvLeft, 0);
			res = Recv(pkt, cur, cubRecvLeft);
			if(res > 0) {
				cubRecvLeft -= res;
				cur += res;
				//printf("Receiving data from client %ld: %ld bytes, %lu bytes remain\n", cli.userID, res, cubRecvLeft);
			} else {
				fprintf(stderr, "Client %u timed out\n", cli.userID);
				delete[] bufPktData;
				cli.state = ClientState::End;
				return;
			}
		}

		//printf("Received payload %ld\n", hdr.len);

		if(End(pkt)) {
			switch(hdr.cmd) {
				case CMD_WRITE:
					HandleFileWrite(cli, (Packet_File_Write*)bufPktData);
					break;
				case CMD_READ:
					HandleFileRead(cli, (Packet_File_Read*)bufPktData);
					break;
				case CMD_EXISTS:
					HandleFileExists(cli, (Packet_File_Generic_Path*)bufPktData);
					break;
				case CMD_SIZE:
					HandleFileSize(cli, (Packet_File_Generic_Path*)bufPktData);
					break;
				case CMD_FORGET:
				case CMD_DELETE: // From the viewpoint of the remote, these are equal
					HandleFileDelete(
							cli,
							(Packet_File_Generic_Path*)bufPktData,
							hdr.cmd);
					break;
				case CMD_ACHIEVEMENT:
					HandleAchievement(cli, (Packet_Achievement*)bufPktData);
					break;
				default:
					printf("UNKNOWN COMMAND 0x%x\n", hdr.cmd);
					break;
			}
		} else {
			printf("Received packet with bad signature from %d\n", cli.userID);
			cli.state = ClientState::End;
		}

		delete[] bufPktData;
	} else {
		cli.state = ClientState::End;
	}
}

static void ProcessClient(int sock, const sockaddr_in* addr) {
	int res;
	Client cli;
	if(sock > 0) {
		cli.socket = sock;
		cli.state = ClientState::Start;
		cli.hmacCtx = HMAC_CTX_new();
		printf("Incoming connection %d\n", sock);

		while(cli.state != ClientState::End) {
			switch(cli.state) {
				case ClientState::Start:
					if(!WaitForLoginPacket(cli)) {
						cli.state = ClientState::End;
					}
					break;
				case ClientState::SentLogin:
					AuthenticateClient(cli);
					break;
				case ClientState::Operation:
					ReceiveClientCommand(cli);
					break;
			}
		}

		CloseDatabase();

		close(sock);
		HMAC_CTX_free(cli.hmacCtx);
	}
	printf("Client thread exiting\n");

	_exit(0);
}

static int ServerLoop() {
	int sockServer;
	struct sockaddr_in saddr;
	struct sockaddr_in caddr;
	int one = 1;
	socklen_t clen = sizeof(caddr);

	sockServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(!sockServer) {
		return 1;
	}

	setsockopt(sockServer, SOL_SOCKET, SO_REUSEADDR, (void*)&one, sizeof(one));

	memset(&saddr, 0, sizeof(saddr));

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(NETCLOUD_PORT);

	if(bind(sockServer, (sockaddr*)&saddr, sizeof(saddr)) < 0) {
		perror("ServerLoop: bind() has failed");
		close(sockServer);
		return 1;
	}

	listen(sockServer, 16);
	while(!isShutdown) {
		int sockClient;

		sockClient = accept(sockServer, (sockaddr*)&caddr, &clen);
		if(sockClient > 0) {
			int pidChild = fork();
			if(pidChild == 0) {
				int pidGrandchild = fork();
				if(pidGrandchild == 0) {
					ProcessClient(sockClient, &caddr);
				} else {
					_exit(0);
				}
			} else {
				int wstatus;
				waitpid(pidChild, &wstatus, 0);
			}
		} else {
			perror("accept failed");
		}
	}

	close(sockServer);

	return 0;
}

void SignalHandler(int signal) {
	switch(signal) {
		case SIGTERM:
			isShutdown = true;
			break;
	}
}

int main(int argc, char** argv) {
	isShutdown = false;
	signal(SIGTERM, SignalHandler);
	return ServerLoop();
}
