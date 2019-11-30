#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include "stdio_nc.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <unistd.h>

#define NETCLOUD_BASEDIR "/var/lib/netcloud/"

static void EnsureUserAppDirExists(unsigned long long userID, unsigned long long appID) {
	char buf[2048];

	snprintf(buf, 2048, NETCLOUD_BASEDIR "/%llu/", userID);
	mkdir(buf, 0700);
	snprintf(buf, 2048, NETCLOUD_BASEDIR "/%llu/%llu/", userID, appID);
	mkdir(buf, 0700);
}

FILE* fopen_nc(const char* pchPath, const char* pchMode, unsigned long long userID, unsigned long long appID) {
	char baseDir[2048];
	char filePath[2048];
	EnsureUserAppDirExists(userID, appID);

	snprintf(baseDir, 2048, NETCLOUD_BASEDIR "/%llu/%llu", userID, appID);

	snprintf(filePath, 2048, "%s/%s", baseDir, pchPath);

	if(strcmp(dirname(filePath), baseDir) == 0) {
		snprintf(filePath, 2048, "%s/%s", baseDir, pchPath);
		return fopen(filePath, pchMode);
	} else {
		printf("Bad directories: %s %s\n", baseDir, filePath);
		return NULL;
	}
}

void remove_nc(const char* pchPath, unsigned long long userID, unsigned long long appID);
