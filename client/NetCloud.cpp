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

#include <unordered_map>

using Achi_Cache = std::unordered_map<std::string, bool>;

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
    HMAC_CTX* ctx;
    int c;
};

using Signed_Packet = SignedPacket;

static void Begin(SignedPacket& pkt, SOCKET s, const Session_Key& session) {
    pkt.ctx = HMAC_CTX_new();
    HMAC_Init_ex(pkt.ctx, session, SESSION_KEY_LEN, EVP_sha256(), NULL);
    pkt.c = 0; // init:0, sending:1, recving:2
    pkt.socket = s;
}

static int Send(SignedPacket& pkt, const void* buf, int len) {
    assert(pkt.c == 1 || pkt.c == 0);
    pkt.c = 1;
    HMAC_Update(pkt.ctx, (unsigned char*)buf, len);
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
    HMAC_Update(pkt.ctx, (unsigned char*)buf, ret);
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
    
    HMAC_Final(pkt.ctx, hmacCalc, &cubMD);
    HMAC_CTX_free(pkt.ctx);
    
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
    m_state(NCState::LoggedOut),
    m_achiCacheInvalid(true) {
        
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
        SignedPacket pkt;
        Packet_Login pktLogin;
        Packet_Auth_Challenge pktChallenge;
        Packet_Auth_Answer pktAnswer;
        Packet_Auth_Result pktResult;
        // Assuming that CDebugLog already initialized WSA
        
        m_achiCacheInvalid = true;
        
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
        pktLogin.hdr = MakeHeader(CMD_LOGIN, sizeof(pktLogin));
        pktLogin.userID = userID;
        pktLogin.appID = appID;
        send(m_hSocket, (char*)&pktLogin, sizeof(pktLogin), 0);

        m_state = NCState::SentLogin;

        // Receive challenge
        BEGIN_PACKET(pkt);
        Recv(pkt, pktChallenge);
        End(pkt);
        // Create session key
        CreateSessionKey(m_sessionKey, pktChallenge.shared, m_pchKey);
        delete[] m_pchKey;
        // Sign the challenge
        SignBytes(pktAnswer.answer, pktChallenge.challenge, 32, m_sessionKey);
        // Send response
        pktAnswer.hdr = MakeHeader(CMD_AUTH, sizeof(pktAnswer));
        BEGIN_PACKET(pkt);
        Send(pkt, pktAnswer);
        End(pkt);
        m_state = NCState::AnswerSent;

        // Receive auth result
        BEGIN_PACKET(pkt);
        Recv(pkt, pktResult);
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
        m_achiCacheInvalid = true;
        m_achiCache.clear();
        return NetCloudResult::OK;
    }

    virtual NetCloudResult FileWrite(const char* pchFile, const void* pvData, int cubData) override {
        if (m_state == NCState::Operation) {
            SignedPacket pkt;
            Packet_File_Write wr;
            Packet_File_Write_Result wrr;
            wr.cubFileName = strlen(pchFile);
            wr.cubFileContents = cubData;
            wr.hdr = MakeHeader(CMD_WRITE, sizeof(wr) + wr.cubFileName + wr.cubFileContents);
            
            // Send file write request
            BEGIN_PACKET(pkt);
            Send(pkt, wr);
            Send(pkt, pchFile, wr.cubFileName);
            Send(pkt, pvData, wr.cubFileContents);
            End(pkt);

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
            int res;
            Packet_File_Read rr;
            Packet_File_Read_Result rrr;
            SignedPacket pkt;

            rr.maxReadBytes = *cubData;
            rr.cubFileName = strlen(pchFile);
            rr.hdr = MakeHeader(CMD_READ, sizeof(rr) + rr.cubFileName);

            // Send file write request
            BEGIN_PACKET(pkt);
            Send(pkt, rr);
            Send(pkt, pchFile, rr.cubFileName);
            End(pkt);

            // Receive file read result header
            BEGIN_PACKET(pkt);
            Recv(pkt, rrr);

            int32 cubRecvLeft = rrr.readBytes;
            assert(rrr.readBytes <= *cubData);
            char* bufRecv = (char*)pvData;

            while (cubRecvLeft > 0) {
                res = Recv(pkt, bufRecv, cubRecvLeft);
                if (res > 0) {
                    cubRecvLeft -= res;
                    bufRecv += res;
                } else {
                    // TODO: error handling
                }
            }
            
            if(End(pkt)) {
                *cubData = rrr.readBytes;
                return NetCloudResult::OK;
            } else {
                *cubData = -1;
                return NetCloudResult::Fail;
            }
        } else {
            return NetCloudResult::Fail;
        }
    }

    virtual NetCloudResult FileForget(bool* pResult, const char* pchFile) override {
        return NetCloudResult();
    }

    NetCloudResult SendGenericPathCommand(int cmd, const char* pchFile) {
        int res;
        bool ok;
        Packet_File_Generic_Path pktReq;
        SignedPacket pkt;
        assert(pchFile);
        
        BEGIN_PACKET(pkt);
		pktReq.cubFileName = strlen(pchFile);
        pktReq.hdr = MakeHeader(cmd, sizeof(pktReq) + pktReq.cubFileName);

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
        int res;
        bool ok;
        Packet_Achievement pktAchi;
        SignedPacket pkt;

        if(pchName) {
            pktAchi.cubNameLen = strlen(pchName);
        } else {
            pktAchi.cubNameLen = 0;
        }
        pktAchi.op = op;
        pktAchi.hdr = MakeHeader(CMD_ACHIEVEMENT, sizeof(pktAchi) + pktAchi.cubNameLen);

        BEGIN_PACKET(pkt);
        res  = Send(pkt, pktAchi);
        if(pktAchi.cubNameLen > 0) {
            res += Send(pkt, pchName, pktAchi.cubNameLen);
        }
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
            if(!m_achiCacheInvalid) {
                if (m_achiCache.count(pchName)) {
                    *pbAchieved = m_achiCache[pchName];
                } else {
                    *pbAchieved = false;
                }
                ret = NetCloudResult::OK;
            } else {
                CacheAchievements();
                ret = GetAchievement(pchName, pbAchieved);
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
                m_achiCache[pchName] = true;
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
                m_achiCache[pchName] = false;
            } else {
                ret = res;
            }
        }

        return ret;
    }
    
    void CacheAchievements() {
        Packet_Achievement_Bulk_Result pktResult;
        Signed_Packet sp;
        uint32 cubNameLen = 0;
        
        m_achiCacheInvalid = true;
        m_achiCache.clear();
        
        if (m_state == NCState::Operation) {
            auto res = SendAchievementOperationPacket(NULL, OP_ACHI_BLKGET);
            if (res == NetCloudResult::OK) {
                BEGIN_PACKET(sp);
                
                Recv(sp, pktResult);
                
                char buf[1024];

                do {
                    Recv(sp, cubNameLen);
                    assert(cubNameLen < 1024);
                    Recv(sp, buf, cubNameLen);
                    buf[cubNameLen] = 0;
                    m_achiCache[buf] = true;
                } while (cubNameLen != 0);
                
                if(End(sp)) {
                    m_achiCacheInvalid = false;
                }
            } else {
            }
        }
    }

private:
    SOCKET m_hSocket;
    char* m_pchKey;
    uint64 m_iUserID;
    Session_Key m_sessionKey;
    NCState m_state;
    
    Achi_Cache m_achiCache;
    bool m_achiCacheInvalid;
};

INetCloudSession* CreateNetCloudSession() {
    return new CNetCloudSession;
}
