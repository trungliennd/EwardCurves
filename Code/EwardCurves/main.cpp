#include "ImplicitCertificate.h"
using namespace Cryptography;

int main() {

   // createPairKey_ku_vs_Ru((char*)"ca",(char*)"ca.pub");
 /*   loadKey_new((char*)"Bob",(char*)"Bob.pub");
    unsigned char key[64];
    ellipticCurvePointToString(Ru.x_.i_, Ru.y_.i_, key, 64);
    cert_Request((char*)"Bob",(unsigned char*)base64_encode(key,64).c_str(), (char*)"cert_bob.crt");*/
    create_certificate((char*)"cert_bob.crt",(char*)"certificate_bob.crt");
    struct cert certificate;
    loadCertificate(certificate, (char*)"certificate_bob.crt");
   // printCertificate(certificate,(char*)"cc.crt");
    bool a = checkCertificate(certificate);
    if(a) {
        printf("case");
    }
    recoverQ_u_vs_du(certificate, (char*)"Bob", (char*)"Bob_s",(char*)"Bob_s.pub");
  //  loadKey_ca((char*)"ca",(char*)"ca.pub");
   //checkKeyExtract(d_ca, Qca);*/
 /*  initCurveTwistEwards25519();
   string s((char*)"b1hDRX1QQNFfWyKRLseCyKd2DnhaTpaMJ5aCxHr+ig9cwceO2dQt7//jcjxtnK77iP6GPborQ5dRI+zqjalQDQ==");
   unsigned char* test = (unsigned char*)base64_decode(s).c_str();
   ed25519::Point q;
   mpz_t x,y;
   mpz_init(x);
   mpz_init(y);
   stringToEllipticCurvePoint(x, y, test, 64);
   q.assignPoint(x, y, *Ed_curves25519);
   q.printPoint();
 //  unsigned char* test1 = enCodeCert(q, (char*)"Bob", (char*)"Thu Apr 19 11:16:26 2018");
  // printKey(test1, 32);*/
}
