#include <math.h>
#include "FinteFiledElement.h"
#include "base64.h"
#include <string.h>
using namespace Cryptography;

void sha256(char *string, unsigned char hash_code[32]);
void HashModul(char *string, mpz_t rs, unsigned int hash_bits, unsigned int modul_bits, void(*function)(char *string, char *out));
void stringToInteger(unsigned char decode[], mpz_t &num_decode, unsigned int bytes);
void cert_Request(char identity[]);
void ellipticCurvePointToString(mpz_t& x, mpz_t& y, unsigned char string_point[], int bytes);
void stringToEllipticCurvePoint(mpz_t& x, mpz_t& y, unsigned char string_point[], int bytes);
void createPairKey_ku_vs_Ru(char* file_ku, char* file_Ru);

ed25519::Point Ru;
ed25519::Point Pu;
ed25519::Point Qu;
mpz_t ku;
mpz_t k_ca;
mpz_t d_ca;
mpz_t r;

unsigned char publicKey25519[crypto_sign_ed25519_PUBLICKEYBYTES];  // use 32 bytes
unsigned char secretKey25519[crypto_sign_ed25519_SECRETKEYBYTES];  // use 32 bytes
unsigned char sharesKey25519[crypto_sign_ed25519_SHAREDKEYBYTES]; // use 32 bytes
unsigned char nonce[crypto_secretbox_NONCEBYTES];  // use 24 bytes

void copyKey(unsigned char *a,const char* b,int len) {
    for(int i =0 ;i < len;i++) {
        a[i] = b[i];
    }
}

void str_inv_copy(unsigned char des[], unsigned char src[], int len) {
        for(int i = 0;i < len;i++) {
            des[len - i - 1] = src[i];
        }
        des[len] = '\0';
}

void sha256(char *string, unsigned char hash_code[32]) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash_code, &sha256);
}

// modul n = 2^252 + 27742317777372353535851937790883648493
void hashModul(char *string_hash, mpz_t &rs, unsigned int hash_bits, unsigned int modul_bits, void(*function)(char *string,unsigned char *out)) {
    unsigned char output[32];
    function(string_hash, output);
    unsigned char andBits[5] = {0xff, 0x7f, 0x3f, 0x1f, 0x0f};
    int num_bits = hash_bits - modul_bits;
    output[0] = ( output[0] & andBits[num_bits]);
    stringToInteger(output, rs, 32);
}



void stringToInteger(unsigned char hash[], mpz_t &num_decode, unsigned int bytes) {
    char out[65];
    int i = 0;
    for(i = 0; i < bytes; i++){
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[64] = 0;
    mpz_set_str(num_decode,out, 16);
}

void createPairKey_ku_vs_Ru(char* file_ku, char* file_Ru) {
    if(Ed_curves25519 == NULL) {
        initCurveTwistEwards25519();
    }
    mpz_init(ku);
    randNumberSecretKey(ku);
   // gmp_printf("\nk_create is: %Zd",ku);
    unsigned char key_ku[32];
    crypto_encode_ed225519_ClampC(key_ku, ku, 32);
    ed25519::Point q;
    q.scalarMultiply(ku, Ed_curves25519->returnGx());
    unsigned char key_Ru[64];
    ellipticCurvePointToString(q.x_.i_, q.y_.i_, key_Ru, 64);
    FILE* out1 = fopen(file_ku, "w");
    if(out1 == NULL) {
        printf("\nWrite secretKey Fail");
        exit(1);
    }else {
        string secret = base64_encode(key_ku,crypto_sign_ed25519_SECRETKEYBYTES);
        int len = secret.length();
        fprintf(out1,"---------------- SECERT KEY ----------------\n");
        fwrite(secret.c_str(),1,len,out1);
        fprintf(out1,"\n--------------------------------------------");
    }
    fclose(out1);
    FILE* out2 = fopen(file_Ru, "w");
    if(out2 == NULL) {
        printf("\nWrite pubKey Fail");
        exit(1);
    }else {
        string pubkey = base64_encode(key_Ru,crypto_sign_ed25519_PUBLICKEYBYTES_D);
        int len = pubkey.length();
        fprintf(out2,"-------------------------------------- PUBLIC KEY --------------------------------------\n");
        fwrite(pubkey.c_str(),1,len,out2);
        fprintf(out2,"\n----------------------------------------------------------------------------------------");
    }
    fclose(out2);
}


void loadKey_new(char*file_ku, char*file_Ru) {
    // secret key
    FILE* readFile = fopen(file_ku, "r");
    if(readFile == NULL) {
        printf("\nCan't read secretKey");
        exit(EXIT_FAILURE);
    }else {
        unsigned char key_ku[BASE64_LEN];
        fread(key_ku,1,BASE64_LEN,readFile);
        fscanf(readFile,"%c",&key_ku[BASE64_LEN - 1]);
        fread(key_ku,1,BASE64_LEN,readFile);
        key_ku[BASE64_LEN] = '\0';
        string s((char*)key_ku);
        mpz_init(ku);
        crypto_decode_ed225519_ClampC((unsigned char*)base64_decode(s).c_str(), ku, 32);
    }
    fclose(readFile);
    FILE* readFile1 = fopen(file_Ru, "r");
    if(readFile1 == NULL) {
        printf("\nCan't read publicKey");
        exit(EXIT_FAILURE);
    }else {
        unsigned char pub[BASE64_LEN_D];
        fread(pub,1,BASE64_LEN_D,readFile1);
        fscanf(readFile1,"%c",&pub[BASE64_LEN_D - 1]);
        fread(pub,1,BASE64_LEN_D,readFile1);
        pub[BASE64_LEN_D] = '\0';
        string s((char*)pub);
        printf("\npub1 is: %s",(char*)s.c_str());
        mpz_t x, y;
        mpz_init(x);
        mpz_init(y);
        stringToEllipticCurvePoint(x, y, (unsigned char*)base64_decode(s).c_str(), crypto_sign_ed25519_PUBLICKEYBYTES_D);
        if(Ed_curves25519 == NULL) {
            initCurveTwistEwards25519();
        }
        Ru.assignPoint(x, y, *Ed_curves25519);
    }
    fclose(readFile1);
}

void cert_Request(char identity[], unsigned char key_Ru[], char *file_out) {
    FILE* out = fopen(file_out, "w");
    fprintf(out, "Identity: ");
    int i = 0;
    while(identity != '\0') {
        fprintf(out,"%c",identity[i]);
        i++;
    }
    fprintf(out, "\n");
    fprintf(out, "Key: ");
    i = 0;
    while(key_Ru[i] != '\0') {
        fprintf(out,"%c",key_Ru[i]);
        i++;
    }
    fclose(out);
}



void createPu(ed25519::Point &Ru) {
    if(Ed_curves25519 == NULL) {
        initCurveTwistEwards25519();
    }
    mpz_init(k_ca);
    randNumberSecretKey(k_ca);
    ed25519::Point q;
    q.scalarMultiply(ku, Ed_curves25519->returnGx());
    Pu.add(Ru.x_, Ru.y_, q.x_, q.y_);
}

void enCodeCert(ed25519::Point Pu, char identify[], long time) {

}

void calculate_r_or_du(mpz_t e, mpz_t k, mpz_t r_or_d_ca) {
    if(Ed_curves25519 == NULL) {
        initCurveTwistEwards25519();
    }
    mpz_init(r);
    ffe_t f_e(e, Ed_curves25519->P), f_k(k, Ed_curves25519->P), f_r_or_dca(r_or_d_ca, Ed_curves25519->P),rs;
    rs.mulFiniteFieldElement(f_e, f_k);
    rs.addFiniteFieldElement(rs, f_r_or_dca);
    mpz_set(r, rs.i_);
}


void calculate_Qu(mpz_t e, ed25519::Point Pu, ed25519::Point Q_ca) {
    if(Ed_curves25519 == NULL) {
        initCurveTwistEwards25519();
    }
    ed25519::Point temp(Pu);
    Qu.addDouble(e, temp);
    Qu.add(Qu.x_, Qu.y_, Q_ca.x_, Q_ca.y_);
}



void ellipticCurvePointToString(mpz_t& x, mpz_t& y,unsigned char string_point[], int bytes) {
    unsigned char point_x[32];
    crypto_encode_ed225519_ClampC(point_x, x, 32);
    unsigned char point_y[32];
    crypto_encode_ed225519_ClampC(point_y, y, 32);
    int index = bytes/2;
    for(int i=0;i < index;i++) {
       string_point[i] = point_x[i];
       string_point[index + i] = point_y[i];
    }
}

void stringToEllipticCurvePoint(mpz_t& x, mpz_t& y, unsigned char string_point[], int bytes) {
    int index = bytes/2;
    unsigned char point_x[32];
    unsigned char point_y[32];
    for(int i = 0;i < index;i++) {
        point_x[i] = string_point[i];
        point_y[i] = string_point[index + i];
    }
    crypto_decode_ed225519_ClampC(point_x, x, 32);
    crypto_decode_ed225519_ClampC(point_y, y, 32);
}

