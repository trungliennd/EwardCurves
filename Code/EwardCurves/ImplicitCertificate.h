#include <math.h>
#include "FinteFiledElement.h"
#include <string.h>
using namespace Cryptography;

void sha256(char *string, unsigned char hash_code[32]);
void HashModul(char *string, mpz_t rs, unsigned int hash_bits, unsigned int modul_bits, void(*function)(char *string, char *out));
void stringToInteger(unsigned char decode[], mpz_t &num_decode, unsigned int bytes);

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
