#include <stdio.h>
#include "FinteFiledElement.h"

using namespace Cryptography;
/*
* parameters n in { 2^254 + 8{0, 1, 2, 3, ..., 2^251 -1} }
* parameters q in {0, 1, 2, 3, ..., 2^256 -1}
*/
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
    EdwardsCurve ed;
    mpz_t rs,p,two;
    ed.randomNumber(rs, 256);
    gmp_printf("%Zd\n",rs);
    mpz_init(p);
    mpz_init(two);
    mpz_set_str(p, "1", 10);
    mpz_set_str(two, "2", 10);
    for(int i = 1;i <= 256;i++) {
        mpz_mul(p, p, two);
    }
    gmp_printf("%Zd\n",p);
}
