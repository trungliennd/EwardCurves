#include "FinteFiledElement.h"
#include <iostream>
#include <fstream>
#define MESSAGE_LEN 1024
#define BASE64_LEN 44

using namespace Cryptography;

unsigned char publicKey25519[crypto_sign_ed25519_PUBLICKEYBYTES];  // use 32 bytes
unsigned char secretKey25519[crypto_sign_ed25519_SECRETKEYBYTES];  // use 32 bytes
unsigned char sharesKey25519[crypto_sign_ed25519_SHAREDKEYBYTES]; // user 32 bytes

unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char MESSAGES[MESSAGE_LEN];
unsigned char CIPHERTEXT[MESSAGE_LEN + crypto_aead_aes256gcm_ABYTES];

void encrypto_messages(char file_message[],char file_ciphertext[]);
void decrypto_messages(char file_ciphertext[],char file_message[]);
void createPublicKeyAndSecretKey(char secretKey[],char publicKey[]);
string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
string base64_decode(std::string const& encoded_string);
inline bool is_base64(unsigned char c);

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

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
        printf("\n---------------- PUBLIC KEY ----------------\n");
        printf("%s",pub.c_str());
        printf("\n--------------------------------------------\n");
    }
    fclose(inp);
}

inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {

  string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {

      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }
  return ret;

}


string base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i == 4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}
