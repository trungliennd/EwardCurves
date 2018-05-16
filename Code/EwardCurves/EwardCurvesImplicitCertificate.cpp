#include "ImplicitCertificate.h"
using namespace Cryptography;

int main(int argc, char** argv) {

    if(argv[1] == NULL) {
        printf("\nPlease choose a into -options: -genkey, -genCert, -genReq, -get , -checkCert\n");
        exit(1);
    }

    if(strcmp(argv[1], "-genkey") == 0) {
        printf("\n-genkey");
        if(argv[2] == NULL   || argv[3] == NULL) {
            createPairKey_ku_vs_Ru((char*)"secretKey", (char*)"publicKey");
        }else {
            createPairKey_ku_vs_Ru(argv[2], argv[3]);
        }
        exit(1);
    }

    if(strcmp(argv[1], "-genReq") == 0) {
        printf("\n-genReq");
        if(argv[2] != NULL){
            if(argv[3] != NULL) {
                loadKey_new(NULL, argv[3]);
            }else {
                loadKey_new(NULL, (char*)"publicKey");
            }
            unsigned char pub[64];
            ellipticCurvePointToString(Ru.x_.i_, Ru.y_.i_, pub, 64);
            if(argv[4] != NULL)
                cert_Request(argv[2], (unsigned char*)base64_encode(pub, 64).c_str(),argv[4]);
            else
                cert_Request(argv[2], (unsigned char*)base64_encode(pub, 64).c_str(),(char*)"request.cert");
        }else {
            printf("\nPlease enter Identify ");
        }
        exit(1);
    }

    if(strcmp(argv[1], "-genCert") == 0) {
        printf("\n-genCert");
        if(argv[2] != NULL) {
            if(argv[3] != NULL) {
                create_certificate(argv[2], argv[3]);
            }else {
                create_certificate(argv[2], (char*)"cert.crt");
            }
        }else {
            printf("\nPlease enter request");
        }
        exit(1);
    }

    if(strcmp(argv[1], "-get") == 0) {
        printf("\n-get pair Key");
        if(argv[2] != NULL) {
            struct cert temp;
            loadCertificate(temp, argv[2]);
            if(argv[3] == NULL) {
                printf("\nPlease enter file secretKey");
                exit(1);
            }
            if(argv[4] == NULL || argv[5] == NULL)
                recoverQ_u_vs_du(temp, argv[3], (char*)"secretKey_s", (char*)"publicKey_s");
            else
                recoverQ_u_vs_du(temp, argv[3], argv[4], argv[5]);
        }else {
            printf("\nPlease enter file cert");
            exit(1);
        }
    }

    if(strcmp(argv[1], "-checkCert") == 0) {
        printf("\n-checkCert");
        if(argv[2] == NULL || argv[3] == NULL) {
            printf("\nPlease enter file certificate and file");
        }else {
            struct cert temp;
            loadCertificate(temp, argv[2]);
            checkPublicKey(temp, argv[3]);
        }
        exit(1);
    }


}
