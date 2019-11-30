#pragma once

#ifndef NO_PROTO_TYPEDEFS
#include <stdint.h>

using uint8	= uint8_t;
using uint16	= uint16_t;
using uint32	= uint32_t;
using uint64	= uint64_t;
using int32	= int32_t;
#endif /* NO_PROTO_TYPEDEFS */

#pragma pack(push, 1)

#define CMD_LOGIN       (0x01)
#define CMD_LOGOUT      (0x02)
#define CMD_AUTH        (0x03)
#define CMD_AUTHRES     (0x04)
#define CMD_WRITE       (0x10)
#define CMD_READ        (0x11)
#define CMD_FORGET      (0x12)
#define CMD_DELETE      (0x13)
#define CMD_EXISTS      (0x14)
#define CMD_SIZE        (0x15)

#define NETCLOUD_PORT   12124

struct Packet_Header {
    uint8 cmd;
    uint32 len;
    unsigned char hmac[32];
};

struct Packet_Login {
    Packet_Header hdr;
    uint64 userID;
    uint64 appID;
};

// SessionKey = H(shared, key)
// Answer = H(challenge, SessionKey)
struct Packet_Auth_Challenge {
    Packet_Header hdr;
    uint8 shared[64];
    uint8 challenge[32];
};

struct Packet_Auth_Answer {
    Packet_Header hdr;
    uint8 answer[32]; // contains the HMAC of the challenge packet
};

struct Packet_Auth_Result {
    Packet_Header hdr;
    uint8 result;
};

struct Packet_File_Read {
    Packet_Header hdr;
    int32 maxReadBytes; // Number of maximum bytes to read
    uint32 cubFileName; // Length of the file name following this u32
    // FileName
};

struct Packet_File_Write {
    Packet_Header hdr;
    uint32 cubFileName; // Length of the file name
    int32 cubFileContents; // Length of the file data 
    // FileName
    // FileContents
};

// Used for CMD_FORGET, CMD_DELETE and CMD_EXISTS
struct Packet_File_Generic_Path {
    Packet_Header hdr;
    uint32 cubFileName; // Length of the file name following this u32
    // FileName
};

struct Packet_File_Read_Result {
    Packet_Header hdr;
    int32 readBytes; // Length of the file contents in bytes
    // File contents
};

struct Packet_General_Result {
    Packet_Header hdr;
    uint8 result; // a 0-1 logical value indicating success or failure
};

using Packet_File_Write_Result = Packet_General_Result;
using Packet_File_Exists_Result = Packet_General_Result;
using Packet_File_Delete_Result = Packet_General_Result;
using Packet_File_Forget_Result = Packet_General_Result;

struct Packet_File_Size_Result {
    Packet_Header hdr;
    int32 fileLength; // Length of the file contents in bytes
};

#pragma pack(pop)
