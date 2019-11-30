#pragma once

enum class NetCloudResult {
    OK = 0,             // OK
    Fail,               // General failure
    Unauthorized,       // Unauthorized
    Network,            // Network related error
    Max
};

class INetCloudSession {
public:
    virtual void Release() = 0;
    virtual NetCloudResult Login(unsigned long long userID, const char* userKey, unsigned appID) = 0;
    virtual NetCloudResult Logout() = 0;

    virtual NetCloudResult FileWrite(const char* pchFile, const void* pvData, int cubData) = 0;
    virtual NetCloudResult FileRead(const char* pchFile, void* pvData, int* cubData) = 0;
    virtual NetCloudResult FileForget(bool* pResult, const char* pchFile) = 0;
    virtual NetCloudResult FileDelete(bool* pResult, const char* pchFile) = 0;
    virtual NetCloudResult FileExists(bool* pResult, const char* pchFile) = 0;
    virtual NetCloudResult GetFileSize(int* result, const char* pchFile) = 0;
};

INetCloudSession* CreateNetCloudSession();
