#include "FinteFiledElement.h"
using namespace Cryptography;

int main() {
  /*  printf("Hello World!!");
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
    printKey(secretkey, 32);*/
    //test();
    mpz_t i,rs,p;
    mpz_init(p);
    mpz_init(i);
    mpz_init(rs);
    mpz_set_str(rs, "23332915997458265218400205037098669710608596188041950079527754443675692320696", 10);
    mpz_set_str(i,"34563128621199832493385287467245284216026396144778331940201037560280872499253", 10);
    mpz_set_str(p, "57896044618658097711785492504343953926634992332820282019728792003956564819949", 10);
    mpz_powm_ui(rs, rs, 2, p);
    mpz_powm_ui(i, i, 2, p);
    gmp_printf("\ni is: %Zd\n", i);
    gmp_printf("\nrs is: %Zd\n",rs);

}
