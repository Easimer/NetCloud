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
#include "db.h"

struct Achievement {
	uint32 cubID;
	char* pchID;
	Achievement* pNext;
};

#define APPEND_ACHI() \
	auto id = sqlite3_column_text(pStmt, 0); \
	uint32 len = (uint32)strlen((char*)id); \
	auto cur = new Achievement; \
	cur->cubID = len; \
	cur->pchID = new char[len]; \
	memcpy(cur->pchID, id, len); \
	cur->pNext = NULL; \
	if(last) last->pNext = cur; \
	last = cur; \
	if(!first) first = last;

static void SetAchievement(Client& cli, const Packet_Achievement* pkt) {
	sqlite3* pDB = OpenDatabase();
	sqlite3_stmt* pStmt = NULL;
	int res;
	Packet_General_Result pktResult;
	Signed_Packet sp;

	memset(&pktResult, 0, sizeof(pktResult));

	pktResult.hdr = MakeHeader(CMD_ACHIEVEMENT, sizeof(pktResult));

	if (pDB && pkt->cubNameLen > 0 && pkt->cubNameLen < 512) {
		sqlite3_busy_timeout(pDB, 100);

		res = sqlite3_prepare_v3(pDB,
				"INSERT OR REPLACE INTO AchievementsEarned VALUES(?, ?, ?)", -1,
				0, &pStmt, NULL);
		if (res == SQLITE_OK) {
			res = sqlite3_bind_int64(pStmt, 1, cli.appID);
			assert(res == SQLITE_OK);
			res = sqlite3_bind_text(pStmt, 2, (char*)(pkt + 1), pkt->cubNameLen, NULL);
			assert(res == SQLITE_OK);
			res = sqlite3_bind_int64(pStmt, 3, cli.userID);
			assert(res == SQLITE_OK);
			do {
				res = sqlite3_step(pStmt);
			} while(res == SQLITE_BUSY);

			if (res == SQLITE_DONE || res == SQLITE_OK) {
				pktResult.result = 0x01;
			} else {
				fprintf(stderr, "Failed to set achievement for user %d: SQLite3 error code %d\n", cli.userID, res);
			}
		} else {
			fprintf(stderr, "Failed to prepare for setting an achievement for user %d: SQLite3 error code %d\n", cli.userID, res);
		}

		sqlite3_finalize(pStmt);
	}

	Begin(sp, cli.socket, cli.sessionKey);
	Send(sp, pktResult);
	End(sp);
}

static void GetAchievement(Client& cli, const Packet_Achievement* pkt) {
	sqlite3* pDB = OpenDatabase();
	sqlite3_stmt* pStmt = NULL;
	int res;
	Packet_General_Result pktResult;
	Signed_Packet sp;
	memset(&pktResult, 0, sizeof(pktResult));
	pktResult.hdr = MakeHeader(CMD_ACHIEVEMENT, sizeof(pktResult));

	if (pDB && pkt->cubNameLen > 0 && pkt->cubNameLen < 512) {
		sqlite3_busy_timeout(pDB, 100);

		res = sqlite3_prepare_v3(pDB,
				"SELECT * FROM AchievementsEarned WHERE AppID=? AND SteamID=? AND AchiID=?", -1,
				0, &pStmt, NULL);
		if (res == SQLITE_OK) {
			res = sqlite3_bind_int64(pStmt, 1, cli.appID);
			assert(res == SQLITE_OK);
			res = sqlite3_bind_int64(pStmt, 2, cli.userID);
			assert(res == SQLITE_OK);
			res = sqlite3_bind_text(pStmt, 3, (char*)(pkt + 1), pkt->cubNameLen, NULL);
			assert(res == SQLITE_OK);

			int nCount = 0;

			res = sqlite3_step(pStmt);
			while(res == SQLITE_OK) {
				nCount++;
				res = sqlite3_step(pStmt);
			}

			if (nCount > 0) {
				pktResult.result = 0x01;
			}
		} else {
			fprintf(stderr, "Failed to prepare for getting an achievement for user %d: SQLite3 error code %d\n", cli.userID, res);
		}

		sqlite3_finalize(pStmt);
	}

	Begin(sp, cli.socket, cli.sessionKey);
	Send(sp, pktResult);
	End(sp);
}

static void ClearAchievement(Client& cli, const Packet_Achievement* pkt) {
	sqlite3* pDB = OpenDatabase();
	sqlite3_stmt* pStmt = NULL;
	int res;
	Packet_General_Result pktResult;
	Signed_Packet sp;
	memset(&pktResult, 0, sizeof(pktResult));
	pktResult.hdr = MakeHeader(CMD_ACHIEVEMENT, sizeof(pktResult));

	if (pDB && pkt->cubNameLen > 0 && pkt->cubNameLen < 512) {
		sqlite3_busy_timeout(pDB, 100);

		res = sqlite3_prepare_v3(pDB,
				"DELETE FROM AchievementsEarned WHERE AppID=? AND SteamID=? AND AchiID=?", -1,
				0, &pStmt, NULL);
		if (res == SQLITE_OK) {
			res = sqlite3_bind_int64(pStmt, 1, cli.appID);
			assert(res == SQLITE_OK);
			res = sqlite3_bind_int64(pStmt, 2, cli.userID);
			assert(res == SQLITE_OK);
			res = sqlite3_bind_text(pStmt, 3, (char*)(pkt + 1), pkt->cubNameLen, NULL);
			assert(res == SQLITE_OK);
			do {
				res = sqlite3_step(pStmt);
			} while(res == SQLITE_BUSY);

			if (res == SQLITE_DONE || res == SQLITE_OK) {
				pktResult.result = 0x01;
			} else {
				fprintf(stderr, "Failed to clear an achievement for user %d: SQLite3 error code %d\n", cli.userID, res);
			}
		} else {
			fprintf(stderr, "Failed to prepare for clearing an achievement for user %d: SQLite3 error code %d\n", cli.userID, res);
		}

		sqlite3_finalize(pStmt);
	}

	Begin(sp, cli.socket, cli.sessionKey);
	Send(sp, pktResult);
	End(sp);
}

static void GetAchievementsBulk(Client& cli, const Packet_Achievement* pkt) {
	sqlite3* pDB = OpenDatabase();
	sqlite3_stmt* pStmt = NULL;
	int res;
	const uint32 zero = 0;
	Packet_Achievement_Bulk_Result pktResult;
	Signed_Packet sp;
	pktResult.hdr = MakeHeader(CMD_ACHIEVEMENT, sizeof(pktResult));
	pktResult.op = OP_ACHI_BLKGET;

	fprintf(stderr, "Bulk achievement transfer to user %llu (app %llu)\n", cli.userID, cli.appID);
	Begin(sp, cli.socket, cli.sessionKey);

	if (pDB) {
		sqlite3_busy_timeout(pDB, 100);

		res = sqlite3_prepare_v3(pDB,
				"SELECT AchiID FROM AchievementsEarned WHERE AppID=? AND SteamID=?", -1,
				0, &pStmt, NULL);
		if (res == SQLITE_OK) {
			Achievement *first = NULL, *last = NULL;
			uint32 cubPacket = sizeof(pktResult);

			res = sqlite3_bind_int64(pStmt, 1, cli.appID);
			assert(res == SQLITE_OK);
			res = sqlite3_bind_int64(pStmt, 2, cli.userID);
			assert(res == SQLITE_OK);

			res = sqlite3_step(pStmt);
			// TODO: fix protocol
			// currently the length field in the header doesn't account for the achievement data
			while(res == SQLITE_ROW) {
				//auto id = sqlite3_column_text(pStmt, 0);
				//uint32 len = (uint32)strlen((char*)id);
				//Send(sp, len);
				//Send(sp, id, len);
				APPEND_ACHI();
				fprintf(stderr, "Achievement fetch: %lu '%*.s'\n", last->cubID, last->pchID);
				cubPacket += 4 + last->cubID;
				res = sqlite3_step(pStmt);
			}
			pktResult.hdr.len = cubPacket + 4;
			fprintf(stderr, "Achievement fetch done\n");

			Send(sp, pktResult);

			while(first) {
				Send(sp, first->cubID);
				Send(sp, first->pchID, first->cubID);
				fprintf(stderr, "Achievement sent: %lu '%*.s'\n", first->cubID, first->pchID);
				auto next = first->pNext;
				delete[] first->pchID;
				delete first;
				first = next;
			}
		} else {
			fprintf(stderr, "Failed to prepare for getting an achievement for user %d: SQLite3 error code %d\n", cli.userID, res);
		}

		sqlite3_finalize(pStmt);
	} else {
		pktResult.hdr.len = sizeof(pktResult) + 4;
		Send(sp, pktResult);
	}

	Send(sp, zero);
	End(sp);
}

void HandleAchievement(Client& cli, Packet_Achievement* pkt) {
	assert(pkt);
	switch (pkt->op) {
		case OP_ACHI_SET:
			SetAchievement(cli, pkt);
			break;
		case OP_ACHI_GET:
			GetAchievement(cli, pkt);
			break;
		case OP_ACHI_CLEAR:
			ClearAchievement(cli, pkt);
			break;
		case OP_ACHI_BLKGET:
			GetAchievementsBulk(cli, pkt);
			break;
		default:
			fprintf(stderr, "Unknown CMD_ACHIEVEMENT operation %d, ignoring.\n", pkt->op);
			break;
	}
}
