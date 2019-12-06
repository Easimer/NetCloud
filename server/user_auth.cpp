#include <assert.h>
#include "common.h"
#include "hmac.h"
#include "user_auth.h"
#include "db.h"

bool CreateSessionKeyForUser(
		unsigned char bufSessionKey[32],
		unsigned long long userID,
		const unsigned char shared[64]) {
	bool ret = false;
	int res;
	sqlite3* pDB;
	sqlite3_stmt* pStmt = NULL;
	assert(bufSessionKey && shared);

	if(userID > 0) {
		pDB=  OpenDatabase();
		if(pDB != NULL) {
			res = sqlite3_prepare_v3(pDB, "SELECT Key FROM user WHERE SteamID=?", -1, 0, &pStmt, NULL);
			if(res == SQLITE_OK) {
				res = sqlite3_bind_int64(pStmt, 1, userID);
				if(res == SQLITE_OK) {
					if(sqlite3_step(pStmt) != SQLITE_DONE) {
						auto userKey = sqlite3_column_text(pStmt, 0);
						if(userKey) {
							CreateSessionKey(bufSessionKey, shared, (char*)userKey);
							ret = true;
						} else {
							fprintf(stderr, "User key is NULL!\n");
						}
					} else {
						fprintf(stderr, "No such user!\n");
					}
				} else {
					fprintf(stderr, "Couldn't bind to the SQL statement! (%d)\n", res);
				}
			} else {
				fprintf(stderr, "Couldn't prepare the SQL statement! (%d)\n", res);
			}
			sqlite3_finalize(pStmt);
		} else {
			fprintf(stderr, "Failed to open auth DB! (%d)\n", res);
		}
	} else {
		fprintf(stderr, "Bad UserID: 0\n");
	}

	return ret;
}
