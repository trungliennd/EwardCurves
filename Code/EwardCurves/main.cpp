#include "EwardCurves.h"

using namespace Cryptography;

int main() {
  /*  printf("Hello World!!");
    mpz_t i,p,j;
    mpz_init(i);
    mpz_init(j);
    mpz_init(p);
    mpz_set_str(i, "4872",10);
    mpz_set(p, i);

    test();
   // mpz_t i,rs,p;
   // mpz_init(i);
   // randNumberSecretKey(i);
   // gmp_printf("\nN is: %Zd",i);*/
 //  test();
    char* file = (char*)"Alice";
    char* file1 = (char*)"Alice.pub";
    char* file2 = (char*)"Bob";
    char* file3 = (char*)"Bob.pub";
   // createPublicKeyAndSecretKey(file, file1);
   // createPublicKeyAndSecretKey(file2, file3);
    initCurveTwistEwards25519();
    loadKey(file,file3);
    crypto_scalarmult(sharesKey25519, secretKey25519, publicKey25519);
  //  printKey(sharesKey25519, 32);
   //    loadKey(file2, file1);
   // crypto_scalarmult(sharesKey25519, secretKey25519, publicKey25519);
  //  printKey(sharesKey25519, 32);
}
