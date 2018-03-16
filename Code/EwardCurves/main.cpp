#include "FinteFiledElement.h"
using namespace Cryptography;

int main() {
    printf("Hello World!!");
    mpz_t i,p,j;
    mpz_init(i);
    mpz_init(j);
    mpz_init(p);
    mpz_set_str(i, "4872",10);
    mpz_set(p, i);
    mpz_clear(i);
   // gmp_printf("\n%Zd\n",p);
    initCurveTwistEwards25519();
    unsigned char publickey[32];
    unsigned char secretkey[32];
    crypto_sign_ed25519_keypair(publickey, secretkey, 32);

    printKey(publickey, 32);
    printKey(secretkey, 32);
   // test();
  //  mpz_t j;
   // mpz_init(j);
   // mpz_set_str(j, (char*)e,10);
   // gmp_printf("\nj is: %Zd\n",j);
   // randomNumber(j, 32);
   // unsigned char k = {0x77};
   // char k1[32];
   // char *a = itoa((unsigned int)k, k1, 16);
   // printf("\na is: %s",k1);
 //   mpz_set_str(j, k1, 16);
  //  gmp_printf("\n%ZX\n",j);
  //  curveTwistEwards25519();
    //test();

}
