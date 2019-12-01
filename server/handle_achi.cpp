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

static void SetAchievement(Client& cli, const Packet_Achievement* pkt) {
	sqlite3* pDB = OpenDatabase();
	sqlite3_stmt* pStmt = NULL;
    int res;
    Packet_General_Result pktResult;
    memset(&pktResult, 0, sizeof(pktResult));
    pktResult.hdr.cmd = CMD_ACHIEVEMENT;
    pktResult.hdr.len = sizeof(pktResult);

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

    SignServerPacket(pktResult, cli.sessionKey);
    res = send(cli.socket, &pktResult, sizeof(pktResult), 0);
    assert(res == sizeof(pktResult));
}

static void GetAchievement(Client& cli, const Packet_Achievement* pkt) {
    sqlite3* pDB = OpenDatabase();
	sqlite3_stmt* pStmt = NULL;
    int res;
    Packet_General_Result pktResult;
    memset(&pktResult, 0, sizeof(pktResult));
    pktResult.hdr.cmd = CMD_ACHIEVEMENT;
    pktResult.hdr.len = sizeof(pktResult);

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

    SignServerPacket(pktResult, cli.sessionKey);
    res = send(cli.socket, &pktResult, sizeof(pktResult), 0);
    assert(res == sizeof(pktResult));
}

static void ClearAchievement(Client& cli, const Packet_Achievement* pkt) {
    sqlite3* pDB = OpenDatabase();
	sqlite3_stmt* pStmt = NULL;
    int res;
    Packet_General_Result pktResult;
    memset(&pktResult, 0, sizeof(pktResult));
    pktResult.hdr.cmd = CMD_ACHIEVEMENT;
    pktResult.hdr.len = sizeof(pktResult);

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

    SignServerPacket(pktResult, cli.sessionKey);
    res = send(cli.socket, &pktResult, sizeof(pktResult), 0);
    assert(res == sizeof(pktResult));
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
    default:
        fprintf(stderr, "Unknown CMD_ACHIEVEMENT operation %d, ignoring.\n", pkt->op);
        break;
    }
}
