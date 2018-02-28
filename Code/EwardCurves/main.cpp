#include "FinteFiledElement.h"
using namespace Cryptography;

int main() {
    printf("Hello World!!\n");
 /*   mpz_t i,p,j;
    mpz_init(i);
    mpz_init(j);
    mpz_init(p);
    mpz_set_str(i, "2",10);
    mpz_set_str(j, "3",10);
    mpz_set_str(p, "7", 10);
    FiniteFieldElement ffe(i,p);
    FiniteFieldElement ffe1(j,p);
    FiniteFieldElement rs;
    rs.divFiniteFieldElement(ffe,ffe1);
    rs.printElement();*/
    curveTwistEwards25519();
}
