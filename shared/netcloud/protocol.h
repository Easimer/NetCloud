#pragma once

#ifndef NO_PROTO_TYPEDEFS
#include <stdint.h>

using uint8	= uint8_t;
using uint16	= uint16_t;
using uint32	= uint32_t;
using uint64	= uint64_t;
using int32	= int32_t;
#endif /* NO_PROTO_TYPEDEFS */

#define SESSION_KEY_LEN (32)
#define HMAC_LEN (32)

using Session_Key = unsigned char[SESSION_KEY_LEN];
using HMAC_MD = unsigned char[HMAC_LEN];

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
#define CMD_ACHIEVEMENT (0x16)

#define OP_ACHI_CLEAR   (0x00)
#define OP_ACHI_GET     (0x01)
#define OP_ACHI_SET     (0x02)
#define OP_ACHI_BLKGET  (0x03)

#if WIN32
#define NETCLOUD_PORT   "12124"
#else
#define NETCLOUD_PORT   12124
#endif /* WIN32 */

#define NETCLOUD_PROTOCOL_VERSION (1)

#define IGNORE_HMAC

struct Packet_Header {
    uint8 ver;
    uint8 cmd;
    uint8 flags;
    uint8 unused;
    uint32 len;
    // [ ... Payload ... ]
    // unsigned char hmac[32];
};

struct Packet_Login {
    Packet_Header hdr;
    uint64 userID;
    uint64 appID;
} IGNORE_HMAC;

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

struct Packet_Achievement {
    Packet_Header hdr;
    uint8 op; // Achievement operation, see OP_ACHI_*
    uint32 cubNameLen; // Length of the achievement identifier
    // Achievement identifier
};

struct Packet_Achievement_Bulk_Result {
    Packet_Header hdr;
    uint8 op; // OP_ACHI_BLKGET
};

#pragma pack(pop)

inline Packet_Header MakeHeader(uint8 cmd, uint32 len) {
       return { NETCLOUD_PROTOCOL_VERSION, cmd, 0, 0, len };
}
