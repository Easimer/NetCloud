#include <stdio.h>
#include <stddef.h>
#include "db.h"
#include <sqlite3.h>

static thread_local sqlite3* gpDB = NULL;

sqlite3* OpenDatabase() {
  int res;
  
  if(gpDB == NULL) {
    res = sqlite3_open_v2("/var/lib/netcloud/auth.db", &gpDB, SQLITE_OPEN_READWRITE, "unix");
    if(res != SQLITE_OK) {
      fprintf(stderr, "Failed to open database: error %d\n", res);
    }
  }

  return gpDB;
}

void CloseDatabase() {
  if(gpDB) {
    sqlite3_close(gpDB);
    gpDB = NULL;
  }
}