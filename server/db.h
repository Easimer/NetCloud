#pragma once

#include <sqlite3.h>

sqlite3* OpenDatabase();
void CloseDatabase();