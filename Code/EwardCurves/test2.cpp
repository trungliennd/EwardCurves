#include "ImplicitCertificate.h"
using namespace Cryptography;

int main() {
    initCurveTwistEwards25519();
    mpz_t e,e1,e2,x,y,k,pp;
    mpz_init(x);
    mpz_set_str(x,"20",10);
    mpz_init(y);
    mpz_set_str(y,"32517075907598268699910704746763769990010501320864744921134204113389941927437",10);
                   //57896044618658097711785492504343953926634992332820282019728792003956564819949
                   //1737427404701399116444042797368467720478288955294300229634781561667767700599642943654277
                   //7237005577332262213973186563042994240857116359379907606001950938285454250989
    mpz_init(pp);
    mpz_set_str(pp, "7237005577332262213973186563042994240857116359379907606001950938285454250989", 10);
    mpz_init(e);
    mpz_set_str(e, "32517075907598268699910704746763769990010501320864744921134204113389941927437", 10);
    mpz_init(e1);
    mpz_set_str(e1, "1", 10);
    mpz_init(e2);
    mpz_set_str(e2, "10", 10);
    mpz_init(k);
    mpz_set_str(k , "53431231321", 10);
    ed25519::Point P(x,y,*Ed_curves25519),Q(x,y,*Ed_curves25519),Z(x,y,*Ed_curves25519);
    mpz_mul(e1, e, k);
  //  gmp_printf("\ne1 is: %Zd",e1);
    mpz_mod(e1, e1, pp);
    P.scalarMultiply(e1, Ed_curves25519->returnGx());
    P.printPoint();
    if(Ed_curves25519->checkPoint(P.x_, P.y_)) {
        printf("\ncase1");
    }
    Q.scalarMultiply(e, Ed_curves25519->returnGx());
    Q.scalarMultiply(k, Q);
    Q.printPoint();
    if(Ed_curves25519->checkPoint(Q.x_, Q.y_)) {
        printf("\ncase2");
    }
 //   Z.addDouble(e1,P);
 //   P.printPoint();
  /*  ffe_t rs;
    ffe_t f_x(x,Ed_curves25519->P);
    Ed_curves25519->takeY(rs, f_x);
    rs.printElement();*/

}
