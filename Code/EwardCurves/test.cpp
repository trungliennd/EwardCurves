#include "ImplicitCertificate.h"
using namespace Cryptography;

int main() {
    initCurveTwistEwards25519();
    ed25519::Point P,test,test1;
    loadKey_new((char*)"Bob", (char*)"Bob.pub");
 //   Ru.printPoint();
    mpz_t x,y,e,rs,temp;
    mpz_init(x);
    mpz_init(y);
    mpz_init(temp);
    mpz_init(e);
    mpz_init(du);
    mpz_init(d_ca);
    mpz_init(ku);
    mpz_init(k_ca);
    mpz_init(r);
    mpz_init(rs);
    mpz_set_str(e, "38340948194251555185500412904619373684884350182295553140131858996012893236936", 10);
    mpz_set_str(k_ca, "9045783334", 10);
    mpz_set_str(d_ca, "425638306587506704699731512122928355317925",10);
    mpz_set_str(r, "34430101523035834238611387050935853729306816823981004003050024925435449696743", 10);
    mpz_set_str(du,"21979111193488918950528197602607910051771232871860603737515298277021531324982", 10);
    mpz_set_str(x, "53806748882261740677289838015985568883197612011738599401915351135503566800866", 10);
    mpz_set_str(y, "39623420637703153639039729219022445254073994376879643331333427690558475647344", 10);
    P.assignPoint(x,y, *Ed_curves25519);
    P.scalarMultiply(e, P);
    P.printPoint();
    Ru.scalarMultiply(e, Ru);
    mpz_mul(temp, e, k_ca);
    mpz_fdiv_r(temp, temp, Ed_curves25519->orderG);
    test1.scalarMultiply(temp, Ed_curves25519->returnGx());
    Ru.add(Ru.x_, Ru.y_, test1.x_, test1.y_);
    Ru.printPoint();
  /*  test1.scalarMultiply(k_ca, Ed_curves25519->returnGx());
    test1.add(Ru.x_, Ru.y_, test1.x_, test1.y_);
    test1.printPoint();*/
}
