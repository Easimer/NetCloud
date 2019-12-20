#include "NetCloud.h"

#include <assert.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <netcloud/protocol.h>

enum class NCState {
    LoggedOut, // Before sending the login packet
    SentLogin,
    AnswerSent,
    Operation,
};

#define BEGIN_PACKET(pkt) Begin(pkt, m_hSocket, m_sessionKey)

static void SignBytes(HMAC_MD hmac, const void* buf, unsigned len, const Session_Key& session) {
    unsigned int cubMD = sizeof(HMAC_MD);
    assert(hmac && buf && session);

    HMAC(EVP_sha256(), session, sizeof(Session_Key), (unsigned char*)buf, len, hmac, &cubMD);
}

static void CreateSessionKey(Session_Key& session, const uint8 shared[64], const char* userKey) {
    unsigned int cubMD = sizeof(Session_Key);
    assert(session && shared && userKey);

    HMAC(EVP_sha256(), userKey, strlen(userKey), shared, 64, session, &cubMD);
}

struct SignedPacket {
    SOCKET socket;
    HMAC_CTX ctx;
    int c;
};

static void Begin(SignedPacket& pkt, SOCKET s, const Session_Key& session) {
    HMAC_CTX_init(&pkt.ctx);
    HMAC_Init_ex(&pkt.ctx, session, SESSION_KEY_LEN, EVP_sha256(), NULL);
    pkt.c = 0; // init:0, sending:1, recving:2
    pkt.socket = s;
}

static int Send(SignedPacket& pkt, const void* buf, int len) {
    assert(pkt.c == 1 || pkt.c == 0);
    pkt.c = 1;
    HMAC_Update(&pkt.ctx, (unsigned char*)buf, len);
    return send(pkt.socket, (char*)buf, len, 0);
}

template<typename T>
static int Send(SignedPacket& pkt, const T& buf) {
    return Send(pkt, &buf, sizeof(T));
}

static int Recv(SignedPacket& pkt, void* buf, int len) {
    assert(pkt.c == 2 || pkt.c == 0);
    pkt.c = 2;
    int ret = recv(pkt.socket, (char*)buf, len, 0);
    HMAC_Update(&pkt.ctx, (unsigned char*)buf, ret);
    return ret;
}

template<typename T>
static int Recv(SignedPacket& pkt, T& buf) {
    return Recv(pkt, &buf, sizeof(T));
}

[[nodiscard]]
static bool End(SignedPacket& pkt) {
    unsigned int cubMD = 32;
    unsigned char hmacCalc[32];
    unsigned char hmacRecv[32];
    bool ret;
    
    memset(hmacCalc, 0, 32);
    
    HMAC_Final(&pkt.ctx, hmacCalc, &cubMD);
    HMAC_CTX_cleanup(&pkt.ctx);
    
    switch(pkt.c) {
        case 1:
        ret = send(pkt.socket, (char*)hmacCalc, 32, 0) == 32;
        break;
        case 2:
        recv(pkt.socket, (char*)hmacRecv, 32, 0);
        ret = memcmp(hmacRecv, hmacCalc, 32) == 0;
        break;
        default:
        assert(0);
        break;
    }
    
    return ret;
}

class CNetCloudSession : public INetCloudSession {
public:
    CNetCloudSession() :
        m_hSocket(INVALID_SOCKET),
        m_pchKey(NULL),
        m_iUserID(0),
        m_state(NCState::LoggedOut) {
        
        ENGINE_load_builtin_engines();
        ENGINE_register_all_complete();
    }

    virtual void Release() override {
        Logout();
        delete this;
    }

    virtual NetCloudResult Login(unsigned long long userID, const char* userKey, unsigned appID) override {
        struct addrinfo hints;
        struct addrinfo *addr, *ptr;
        int res;
        //unsigned char bufHMAC[32];
        SignedPacket pkt;
        Packet_Login pktLogin;
        Packet_Auth_Challenge pktChallenge;
        Packet_Auth_Answer pktAnswer;
        Packet_Auth_Result pktResult;
        // Assuming that CDebugLog already initialized WSA

        assert(m_state == NCState::LoggedOut);

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        res = getaddrinfo("steamworks.easimer.net", NETCLOUD_PORT, &hints, &addr);
        if (res != 0) {
            return NetCloudResult::Network;
        }

        for (ptr = addr; ptr; ptr = ptr->ai_next) {
            m_hSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (m_hSocket == INVALID_SOCKET) {
                return NetCloudResult::Network;
            }

            res = connect(m_hSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
            if (res == SOCKET_ERROR) {
                closesocket(m_hSocket);
                m_hSocket = INVALID_SOCKET;
                continue;
            }
            break;
        }

        freeaddrinfo(addr);

        if (m_hSocket == INVALID_SOCKET) {
            return NetCloudResult::Network;
        }

        m_iUserID = userID;
        m_pchKey = new char[strlen(userKey) + 1];
        memcpy(m_pchKey, userKey, strlen(userKey) + 1);
        
        // Send a CMD_LOGIN
        //pktLogin.hdr.cmd = CMD_LOGIN;
        //pktLogin.hdr.len = sizeof(pktLogin);
        pktLogin.hdr = MakeHeader(CMD_LOGIN, sizeof(pktLogin));
        //memset(pktLogin.hdr.hmac, 0, 32);
        pktLogin.userID = userID;
        pktLogin.appID = appID;
        send(m_hSocket, (char*)&pktLogin, sizeof(pktLogin), 0);

        m_state = NCState::SentLogin;

        // Receive challenge
        //Begin(pkt, m_hSocket, m_sessionKey);
        BEGIN_PACKET(pkt);
        Recv(pkt, pktChallenge);
        End(pkt);
        //recv(m_hSocket, (char*)&pktChallenge, sizeof(pktChallenge), 0);
        // Create session key
        CreateSessionKey(m_sessionKey, pktChallenge.shared, m_pchKey);
        delete[] m_pchKey;
        // Sign the challenge
        SignBytes(pktAnswer.answer, pktChallenge.challenge, 32, m_sessionKey);
        // Send response
        //pktAnswer.hdr.cmd = CMD_AUTH;
        //pktAnswer.hdr.len = sizeof(pktAnswer);
        pktAnswer.hdr = MakeHeader(CMD_AUTH, sizeof(pktAnswer));
        //SignClientPacket(pktAnswer, m_sessionKey);
        //send(m_hSocket, (char*)&pktAnswer, sizeof(pktAnswer), 0);
        BEGIN_PACKET(pkt);
        Send(pkt, pktAnswer);
        End(pkt);
        m_state = NCState::AnswerSent;

        // Receive auth result
        //Begin(pkt, m_hSocket, m_sessionKey);
        BEGIN_PACKET(pkt);
        Recv(pkt, pktResult);
        //recv(m_hSocket, (char*)&pktResult, sizeof(pktResult), 0);
        assert(pktResult.hdr.cmd == CMD_AUTHRES);
        if (End(pkt)) {
            if (pktResult.result) {
                m_state = NCState::Operation;
            } else {
                m_state = NCState::LoggedOut;
                return NetCloudResult::Unauthorized;
            }
        } else {
            m_state = NCState::LoggedOut;
            return NetCloudResult::Network;
        }

        return NetCloudResult::OK;
    }

    virtual NetCloudResult Logout() override {
        if (m_hSocket) {
            closesocket(m_hSocket);
            m_hSocket = INVALID_SOCKET;
        }
        if (m_pchKey) {
            delete[] m_pchKey;
        }
        m_iUserID = 0;
        m_state = NCState::LoggedOut;
        return NetCloudResult::OK;
    }

    virtual NetCloudResult FileWrite(const char* pchFile, const void* pvData, int cubData) override {
        if (m_state == NCState::Operation) {
            //unsigned int cubMD = 32;
            //int res;
            //HMAC_CTX ctx;
            SignedPacket pkt;
            Packet_File_Write wr;
            Packet_File_Write_Result wrr;
            //wr.hdr.cmd = CMD_WRITE;
            wr.cubFileName = strlen(pchFile);
            wr.cubFileContents = cubData;
            //wr.hdr.len = sizeof(wr) + wr.cubFileName + wr.cubFileContents;
            wr.hdr = MakeHeader(CMD_WRITE, sizeof(wr) + wr.cubFileName + wr.cubFileContents);
            //memset(wr.hdr.hmac, 0, HMAC_LEN);
            
            BEGIN_PACKET(pkt);
            Send(pkt, wr);
            Send(pkt, pchFile, wr.cubFileName);
            Send(pkt, pvData, wr.cubFileContents);
            End(pkt);

            // Send file write request
            //res  = send(m_hSocket, (char*)&wr, sizeof(wr), 0);
            //res += send(m_hSocket, (char*)pchFile, wr.cubFileName, 0);
            //res += send(m_hSocket, (char*)pvData, wr.cubFileContents, 0);

            // Receive file write confirmation
            BEGIN_PACKET(pkt);
            Recv(pkt, wrr);
            if(End(pkt)) {
                return wrr.result == 0x01 ? NetCloudResult::OK : NetCloudResult::Fail;
            } else {
                return NetCloudResult::Fail;
            }
        } else {
            return NetCloudResult::Fail;
        }
    }

    virtual NetCloudResult FileRead(const char* pchFile, void* pvData, int* cubData) override {
        if (m_state == NCState::Operation) {
            //unsigned int cubMD = 32;
            //HMAC_MD hmacCalculatedResult, hmacResultOriginal;
            int res;
            //HMAC_CTX ctx;
            Packet_File_Read rr;
            Packet_File_Read_Result rrr;
            SignedPacket pkt;

            //rr.hdr.cmd = CMD_READ;
            rr.maxReadBytes = *cubData;
            rr.cubFileName = strlen(pchFile);
            //rr.hdr.len = sizeof(rr) + rr.cubFileName;
            //memset(rr.hdr.hmac, 0, HMAC_LEN);
            rr.hdr = MakeHeader(CMD_READ, sizeof(rr) + rr.cubFileName);

            //HMAC_CTX_init(&ctx);
            //HMAC_Init_ex(&ctx, m_sessionKey, SESSION_KEY_LEN, EVP_sha256(), NULL);
            //HMAC_Update(&ctx, (unsigned char*)&rr, sizeof(rr));
            //HMAC_Update(&ctx, (unsigned char*)pchFile, rr.cubFileName);
            //HMAC_Final(&ctx, rr.hdr.hmac, &cubMD);
            //HMAC_CTX_cleanup(&ctx);

            // Send file write request
            //res  = send(m_hSocket, (char*)&rr, sizeof(rr), 0);
            //res += send(m_hSocket, (char*)pchFile, rr.cubFileName, 0);
            BEGIN_PACKET(pkt);
            Send(pkt, rr);
            Send(pkt, pchFile, rr.cubFileName);
            End(pkt);

            // Receive file read result header
            //res = recv(m_hSocket, (char*)&rrr, sizeof(rrr), 0);
            BEGIN_PACKET(pkt);
            Recv(pkt, rrr);

            // Manual authentication
            //memcpy(hmacResultOriginal, rrr.hdr.hmac, HMAC_LEN);
            //memset(rrr.hdr.hmac, 0, HMAC_LEN);
            //HMAC_CTX_init(&ctx);
            //HMAC_Init_ex(&ctx, m_sessionKey, SESSION_KEY_LEN, EVP_sha256(), NULL);
            //HMAC_Update(&ctx, (unsigned char*)&rrr, sizeof(rrr));

            int32 cubRecvLeft = rrr.readBytes;
            assert(rrr.readBytes <= *cubData);
            char* bufRecv = (char*)pvData;

            while (cubRecvLeft > 0) {
                //res = recv(m_hSocket, bufRecv, cubRecvLeft, 0);
                res = Recv(pkt, bufRecv, cubRecvLeft);
                if (res > 0) {
                    //HMAC_Update(&ctx, (unsigned char*)bufRecv, res);
                    cubRecvLeft -= res;
                    bufRecv += res;
                } else {
                    // TODO: error handling
                }
            }

            //HMAC_Final(&ctx, hmacCalculatedResult, &cubMD);
            //HMAC_CTX_cleanup(&ctx);
            
            if(End(pkt)) {
                *cubData = rrr.readBytes;
                return NetCloudResult::OK;
            } else {
                *cubData = -1;
                return NetCloudResult::Fail;
            }

            //if (memcmp(hmacCalculatedResult, hmacResultOriginal, HMAC_LEN) == 0) {
                //*cubData = rrr.readBytes;

                //return NetCloudResult::OK;
            //} else {
                //*cubData = -1;
                //return NetCloudResult::Fail;
            //}
        } else {
            return NetCloudResult::Fail;
        }
    }

    virtual NetCloudResult FileForget(bool* pResult, const char* pchFile) override {
        return NetCloudResult();
    }

    NetCloudResult SendGenericPathCommand(int cmd, const char* pchFile) {
            //HMAC_CTX ctx;
            //unsigned int cubMD = 32;
        int res;
        bool ok;
        Packet_File_Generic_Path pktReq;
        SignedPacket pkt;
        assert(pchFile);
        
        BEGIN_PACKET(pkt);
            //pktReq.hdr.cmd = cmd;
            pktReq.cubFileName = strlen(pchFile);
        //pktReq.hdr.len = sizeof(pktReq) + pktReq.cubFileName;
        pktReq.hdr = MakeHeader(cmd, sizeof(pktReq) + pktReq.cubFileName);

            //memset(pktReq.hdr.hmac, 0, HMAC_LEN);

            //HMAC_CTX_init(&ctx);
            //HMAC_Init_ex(&ctx, m_sessionKey, SESSION_KEY_LEN, EVP_sha256(), NULL);
            //HMAC_Update(&ctx, (unsigned char*)&pktReq, sizeof(pktReq));
            //HMAC_Update(&ctx, (unsigned char*)pchFile, pktReq.cubFileName);
            //HMAC_Final(&ctx, pktReq.hdr.hmac, &cubMD);
            //HMAC_CTX_cleanup(&ctx);
            
            //res  = send(m_hSocket, (char*)&pktReq, sizeof(pktReq), 0);
        //res += send(m_hSocket, (char*)pchFile, pktReq.cubFileName, 0);
        res  = Send(pkt, pktReq);
        res += Send(pkt, pchFile, pktReq.cubFileName);
            assert(res == sizeof(pktReq) + pktReq.cubFileName);
        
        ok = End(pkt);
        
            if (res == sizeof(pktReq) + pktReq.cubFileName && ok) {
                return NetCloudResult::OK;
            } else {
                return NetCloudResult::Network;
            }
    }

    template<typename T>
    NetCloudResult ReceiveFixedSizePacket(T* pktResult) {
        int res;
        bool ok;
        SignedPacket pkt;
        
        BEGIN_PACKET(pkt);
        res = Recv(pkt, pktResult, sizeof(T));
        ok = End(pkt);
        
        if(res == sizeof(T) && ok) {
            if(ok) {
                return NetCloudResult::OK;
            } else {
                return NetCloudResult::Unauthorized;
            }
        } else {
            return NetCloudResult::Network;
        }
        
        //res = recv(m_hSocket, (char*)pktResult, sizeof(*pktResult), 0);
        //assert(res == sizeof(*pktResult));
        //if (res == sizeof(*pktResult)) {
            //if (AuthenticateServerPacket(*pktResult, m_sessionKey)) {
                //return NetCloudResult::OK;
            //} else {
                //return NetCloudResult::Unauthorized;
            //}
        //} else {
            //return NetCloudResult::Network;
        //}
    }

    NetCloudResult ReceiveGenericResult(Packet_General_Result* pktResult) {
        return ReceiveFixedSizePacket(pktResult);
    }

    virtual NetCloudResult FileDelete(bool* pResult, const char* pchFile) override {
        NetCloudResult res;
        if (m_state == NCState::Operation) {
            Packet_General_Result pktResult;
            
            res = SendGenericPathCommand(CMD_EXISTS, pchFile);

            if(res == NetCloudResult::OK) {
                res = ReceiveGenericResult(&pktResult);

                if (res == NetCloudResult::OK) {
                    *pResult = pktResult.result == 0x01;
                    return NetCloudResult::OK;
                } else {
                    return res;
                }
            } else {
                return res;
            }
        } else {
            return NetCloudResult::Fail;
        }
    }

    virtual NetCloudResult FileExists(bool* pResult, const char* pchFile) override {
        NetCloudResult res;
        if (m_state == NCState::Operation) {
            Packet_General_Result pktResult;
            
            res = SendGenericPathCommand(CMD_EXISTS, pchFile);

            if(res == NetCloudResult::OK) {
                res = ReceiveGenericResult(&pktResult);

                if (res == NetCloudResult::OK) {
                    *pResult = pktResult.result == 0x01;
                    return NetCloudResult::OK;
                } else {
                    return res;
                }
            } else {
                return res;
            }
        } else {
            return NetCloudResult::Fail;
        }
    }

    virtual NetCloudResult GetFileSize(int* result, const char* pchFile) override {
        NetCloudResult res;
        if (m_state == NCState::Operation) {
            Packet_File_Size_Result pktResult;
            
            res = SendGenericPathCommand(CMD_SIZE, pchFile);

            if(res == NetCloudResult::OK) {
                res = ReceiveFixedSizePacket(&pktResult);

                if (res == NetCloudResult::OK) {
                    *result = pktResult.fileLength;
                    return NetCloudResult::OK;
                } else {
                    return res;
                }
            } else {
                return res;
            }
        } else {
            return NetCloudResult::Fail;
        }
    }

    NetCloudResult SendAchievementOperationPacket(const char* pchName, int op) {
        NetCloudResult ret = NetCloudResult::Fail;
        //HMAC_CTX ctx;
        //unsigned int cubMD = 32;
        int res;
        bool ok;
        Packet_Achievement pktAchi;
        SignedPacket pkt;

        assert(pchName);

        //pktAchi.hdr.cmd = CMD_ACHIEVEMENT;
        pktAchi.cubNameLen = strlen(pchName);
        pktAchi.op = op;
        //pktAchi.hdr.len = sizeof(pktAchi) + pktAchi.cubNameLen;
        pktAchi.hdr = MakeHeader(CMD_ACHIEVEMENT, sizeof(pktAchi) + pktAchi.cubNameLen);

        //memset(pktAchi.hdr.hmac, 0, HMAC_LEN);

        //HMAC_CTX_init(&ctx);
        //HMAC_Init_ex(&ctx, m_sessionKey, SESSION_KEY_LEN, EVP_sha256(), NULL);
        //HMAC_Update(&ctx, (unsigned char*)&pktAchi, sizeof(pktAchi));
        //HMAC_Update(&ctx, (unsigned char*)pchName, pktAchi.cubNameLen);
        //HMAC_Final(&ctx, pktAchi.hdr.hmac, &cubMD);
        //HMAC_CTX_cleanup(&ctx);

        //res = send(m_hSocket, (char*)&pktAchi, sizeof(pktAchi), 0);
        //res += send(m_hSocket, (char*)pchName, pktAchi.cubNameLen, 0);
        //assert(res == sizeof(pktAchi) + pktAchi.cubNameLen);
        BEGIN_PACKET(pkt);
        res  = Send(pkt, pktAchi);
        res += Send(pkt, pchName, pktAchi.cubNameLen);
        ok = End(pkt);

        if (res == sizeof(pktAchi) + pktAchi.cubNameLen && ok) {
            return NetCloudResult::OK;
        } else {
            return NetCloudResult::Network;
        }

        return ret;
    }

    virtual NetCloudResult GetAchievement(const char* pchName, bool* pbAchieved) override {
        auto ret = NetCloudResult::Fail;
        Packet_General_Result pktResult;
        assert(pchName && pbAchieved);

        if (m_state == NCState::Operation) {
            auto res = SendAchievementOperationPacket(pchName, OP_ACHI_GET);
            if (res == NetCloudResult::OK) {
                res = ReceiveFixedSizePacket(&pktResult);
                if (res == NetCloudResult::OK) {
                    *pbAchieved = pktResult.result == 0x01;
                    ret = NetCloudResult::OK;
                }
            } else {
                ret = res;
            }
        }

        return ret;
    }

    virtual NetCloudResult SetAchievement(const char* pchName) override {
        auto ret = NetCloudResult::Fail;
        Packet_General_Result pktResult;
        assert(pchName);

        if (m_state == NCState::Operation) {
            auto res = SendAchievementOperationPacket(pchName, OP_ACHI_SET);
            if (res == NetCloudResult::OK) {
                res = ReceiveFixedSizePacket(&pktResult);
                if (res == NetCloudResult::OK) {
                    ret = pktResult.result == 0x01 ? NetCloudResult::OK : NetCloudResult::Fail;
                }
            } else {
                ret = res;
            }
        }

        return ret;
    }

    virtual NetCloudResult ClearAchievement(const char* pchName) override {
        auto ret = NetCloudResult::Fail;
        Packet_General_Result pktResult;
        assert(pchName);

        if (m_state == NCState::Operation) {
            auto res = SendAchievementOperationPacket(pchName, OP_ACHI_CLEAR);
            if (res == NetCloudResult::OK) {
                res = ReceiveFixedSizePacket(&pktResult);
                if (res == NetCloudResult::OK) {
                    ret = pktResult.result == 0x01 ? NetCloudResult::OK : NetCloudResult::Fail;
                }
            } else {
                ret = res;
            }
        }

        return ret;
    }

private:
    SOCKET m_hSocket;
    char* m_pchKey;
    uint64 m_iUserID;
    Session_Key m_sessionKey;
    NCState m_state;
};

INetCloudSession* CreateNetCloudSession() {
    return new CNetCloudSession;
}
