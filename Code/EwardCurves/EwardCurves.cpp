#include "EwardCurves.h"

int main(int argc, char **argv) {

    if(argv[1] == NULL) {
        printf("\nPlease choose a into -options: -genkey, -en, -de\n");
        exit(1);
    }

    if(strcmp(argv[1], "-genkey") == 0) {
        printf("\n-genkey");
        if(argv[2] == 0 || argv[3] == 0) {
            createPublicKeyAndSecretKey((char*)"secretKey", (char*)"publicKey");
        }else {
            createPublicKeyAndSecretKey(argv[2], argv[3]);
        }
    }else if(strcmp(argv[1], "-en") == 0) {
        printf("\n-encrypto");
        if(argv[2] == 0) {
            printf("\nPlease enter message need encrypto");
        }else {
            if(argv[3] != 0) {
                if(argv[4] == 0) {
                    loadKey(argv[3], (char*)"secretKey");
                    encrypto_messages(argv[2], (char*)"ciphertext.txt");
                }else {
                    loadKey(argv[3], argv[4]);
                    if(argv[5] != 0) {
                        encrypto_messages(argv[2], argv[5]);
                    }else {
                        encrypto_messages(argv[2], (char*)"ciphertext.txt");
                    }
                }
            }else {
                printf("\nPlease enter file contain secretkey and publickey of partner");
            }
        }
    }else if(strcmp(argv[1], "-de") == 0) {
        printf("\n-decrypto");
        if(argv[2] == 0) {
            printf("\nPlease enter ciphertex need decryption");
        }else {
            if(argv[3] != 0) {
                if(argv[4] == 0) {
                    loadKey(argv[3], (char*)"secretKey");
                    decrypto_messages(argv[2], (char*)"messages_text.txt");
                }else {
                    loadKey(argv[3], argv[4]);
                    if(argv[5] != 0){
                        decrypto_messages(argv[2], argv[5]);
                    }else {
                        decrypto_messages(argv[2], (char*)"messages_text.txt");
                    }
                }
            }else {
                printf("\nPlease enter file contain secretkey and publickey of partner");
            }
        }
    }else {
        printf("\nNo Have Option %s",argv[1]);
        printf("\nPlease choose a into -options: -genkey, -en, -de");
    }
}
