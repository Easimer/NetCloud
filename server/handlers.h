#pragma once

#include "common.h"
#include <netcloud/protocol.h>

void HandleFileRead(Client& cli, Packet_File_Read* pkt);
void HandleFileWrite(Client& cli, Packet_File_Write* pkt);
void HandleFileExists(Client& cli, Packet_File_Generic_Path* pkt);
void HandleFileSize(Client& cli, Packet_File_Generic_Path* pkt);
void HandleFileDelete(Client& cli, Packet_File_Generic_Path* pkt, int cmdOrig);
