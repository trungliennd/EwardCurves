#include "FinteFiledElement.h"
#include "base64.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#define MESSAGE_LEN 1024
#define BASE64_LEN 44


using namespace Cryptography;
using namespace std;

unsigned char publicKey25519[crypto_sign_ed25519_PUBLICKEYBYTES];  // use 32 bytes
unsigned char secretKey25519[crypto_sign_ed25519_SECRETKEYBYTES];  // use 32 bytes
unsigned char sharesKey25519[crypto_sign_ed25519_SHAREDKEYBYTES]; // use 32 bytes
unsigned char nonce[crypto_secretbox_NONCEBYTES];  // use 24 bytes

//unsigned char MESSAGES[MESSAGE_LEN];
//unsigned char CIPHERTEXT[MESSAGE_LEN + crypto_aead_aes256gcm_ABYTES];

void encrypto_messages(char file_message[],char file_ciphertext[]);
void decrypto_messages(char file_ciphertext[],char file_message[]);
void createPublicKeyAndSecretKey(char secretKey[],char publicKey[]);
string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
string base64_decode(std::string const& encoded_string);
const unsigned int aes_block_SIZE = 32;

struct ctr_state {
    unsigned char  ivec[aes_block_SIZE];
    unsigned int   num;
    unsigned char  ecount[aes_block_SIZE];
};

struct ctr_state state;
AES_KEY key;
unsigned char iv[crypto_secretbox_NONCEBYTES];

int init_ctr(struct ctr_state* state, const unsigned char iv[32]) {
    state->num = 0;
    memset(state->ecount, 0, aes_block_SIZE);
    // initialize counter in ivec to 0
    memset(state->ivec + 16, 0, 8);
    // Copy IV into 'ivec'
    memcpy(state->ivec, iv, 16);
}

void copyKey(unsigned char *a,const char* b,int len) {
    for(int i =0 ;i < len;i++) {
        a[i] = b[i];
    }
}

void encrypto_messages(char file_message[],char file_ciphertext[]) {
    randNonce(iv, 24);
    FILE* readFile = fopen(file_message, "rb");
    FILE* writeFile = fopen(file_ciphertext, "wb");

    if(readFile == NULL) {
        printf("\n Read file is null");
        exit(1);
    }
    if(writeFile == NULL) {
        printf("\n Write file is null");
        exit(1);
    }

    fwrite(iv, 1, 16, writeFile); // IV bytes 1-8
    fwrite("\0\0\0\0\0\0\0\0", 1, 8, writeFile); // fill the last 4 with null bytes 25 - 32

    if(AES_set_encrypt_key(sharesKey25519, 256, &key) < 0) {
        printf("\n Could not set encryption key");
        exit(1);
    }
    init_ctr(&state, iv);

    int bytes_read, bytes_wrriten;
    unsigned char indata[MESSAGE_LEN];
    unsigned char outdata[MESSAGE_LEN];

    while(true) {
        bytes_read = fread(indata, 1, MESSAGE_LEN, readFile);
        AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);

        bytes_wrriten = fwrite(outdata, 1, bytes_read, writeFile);
        if(bytes_read < MESSAGE_LEN) {
            break;
        }
    }

    fclose(readFile);
    fclose(writeFile);
}

void decrypto_messages(char file_ciphertext[], char file_message[]) {
    FILE* readFile = fopen(file_ciphertext, "rb");
    FILE* writeFile = fopen(file_message, "w");
    if(readFile == NULL || writeFile == NULL) {
        printf("\nCan't decrypto ciphertext");
        exit(EXIT_FAILURE);
    }

    fread(iv, 1, 24, readFile);
    if(AES_set_encrypt_key(sharesKey25519,256,&key) < 0) {
        printf("\n Could not set decryption key");
        exit(1);
    }

    init_ctr(&state, iv);
    int bytes_read, byte_writen;
    unsigned char indata[MESSAGE_LEN];
    unsigned char outdata[MESSAGE_LEN];
    while(true) {
        bytes_read = fread(indata, 1, MESSAGE_LEN, readFile);
        AES_ctr128_encrypt(indata, outdata, bytes_read, &key,
                                state.ivec, state.ecount, &state.num);
        byte_writen = fwrite(outdata, 1, bytes_read, writeFile);
        if(bytes_read < MESSAGE_LEN) {
            break;
        }
    }

}

void loadKey(char secretKey[], char publicKey[]) {
    // secret key
    FILE* readFile = fopen(secretKey, "r");
    if(readFile == NULL) {
        printf("\nCan't read secretKey");
        exit(EXIT_FAILURE);
    }else {
        unsigned char secret[BASE64_LEN];
        fread(secret,1,BASE64_LEN,readFile);
        fscanf(readFile,"%c",&secret[BASE64_LEN - 1]);
        fread(secret,1,BASE64_LEN,readFile);
        secret[BASE64_LEN] = '\0';
        string s((char*)secret);
        copyKey(secretKey25519,base64_decode(s).c_str(),crypto_scalarmult_curve25519_BYTES);
    }
    fclose(readFile);

    // public key
    FILE* readFile1 = fopen(publicKey, "r");
    if(readFile1 == NULL) {
        printf("\nCan't read publicKey");
        exit(EXIT_FAILURE);
    }else {
        unsigned char pub[BASE64_LEN];
        fread(pub,1,BASE64_LEN,readFile1);
        fscanf(readFile1,"%c",&pub[BASE64_LEN - 1]);
        fread(pub,1,BASE64_LEN,readFile1);
        pub[BASE64_LEN] = '\0';
        string s((char*)pub);
        copyKey(publicKey25519,base64_decode(s).c_str(),crypto_scalarmult_curve25519_BYTES);
    }
     fclose(readFile1);
     initCurveTwistEwards25519();
     if(crypto_scalarmult(sharesKey25519, secretKey25519, publicKey25519) != 0){
        printf("\nCan't calculation shareKey");
        exit(1);
     }
     printKey(sharesKey25519 ,32);
}

void createPublicKeyAndSecretKey(char secretKey[],char publicKey[]) {

    unsigned char publicKeyEd25519[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char secretKeyEd25519[crypto_sign_ed25519_SECRETKEYBYTES];
    // create key pair

    initCurveTwistEwards25519();
    crypto_sign_ed25519_keypair(publicKeyEd25519,secretKeyEd25519, 32);
    /*
    * write public key and secret key
    */
    FILE *out = fopen(secretKey,"w");
    if(out == NULL) {
        printf("\nWrite secretKey Fail");
        exit(1);
    }else {
        string secret = base64_encode(secretKeyEd25519,crypto_sign_ed25519_SECRETKEYBYTES);
 //       printf("\nS is: \n");
     //   printKey(secretKeyEd25519,32);
        int len = secret.length();
        fprintf(out,"---------------- SECERT KEY ----------------\n");
        fwrite(secret.c_str(),1,len,out);
        fprintf(out,"\n--------------------------------------------");
    }
    fclose(out);
    FILE *inp = fopen(publicKey,"w");
    if(inp == NULL) {
        printf("\nWrite publicKey Fail");
        exit(EXIT_FAILURE);
    }else {
        string pub = base64_encode(publicKeyEd25519,crypto_sign_ed25519_PUBLICKEYBYTES);
        int len = pub.length();
        fprintf(inp,"---------------- PUBLIC KEY ----------------\n");
        fwrite(pub.c_str(),1,len,inp);
        fprintf(inp,"\n--------------------------------------------");
        // public key
     /*   printf("\n---------------- PUBLIC KEY ----------------\n");
        printf("%s",pub.c_str());
        printf("\n--------------------------------------------\n");*/
    }
    fclose(inp);
}

inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

