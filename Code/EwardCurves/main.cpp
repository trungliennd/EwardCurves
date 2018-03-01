#include "FinteFiledElement.h"
using namespace Cryptography;

int main() {
    printf("Hello World!!");
    mpz_t i,p,j;
    mpz_init(i);
    mpz_init(j);
    mpz_init(p);
    mpz_set_str(i, "2",10);
    mpz_set(p, i);
    mpz_clear(i);
   // gmp_printf("\n%Zd\n",p);
    curveTwistEwards25519();
    test();
}
