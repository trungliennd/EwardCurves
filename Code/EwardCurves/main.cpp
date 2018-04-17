#include "ImplicitCertificate.h"
using namespace Cryptography;

int main() {

  /*  loadKey_new((char*)"Bob",(char*)"Bob.pub");
    unsigned char key[64];
    ellipticCurvePointToString(Ru.x_.i_, Ru.y_.i_, key, 64);
    cert_Request((char*)"Bob",(unsigned char*)base64_encode(key,64).c_str(), (char*)"cert_bob.crt");*/
   // create_certificate((char*)"cert_bob.crt",(char*)"certificate_bob.crt");
    struct cert certificate;
    loadCertificate(certificate, (char*)"certificate_bob.crt");
   // printCertificate(certificate,(char*)"cc.crt");
    recoverQ_u_vs_du(certificate, (char*)"Bob", (char*)"Bob_s",(char*)"Bob_s.pub");
    ed25519::Point q;
    mpz_t x,y;
    mpz_init(x);
    mpz_init(y);
    string s((char*)"f8ynhLs55bcf+E5iZpOViUr/qfCJSRGItyHjvDwI7mvZkJ6dFl24QOgrsQ11uYT7hhKq3qCrSE7d7I6fkvTdDA==");
    stringToEllipticCurvePoint(x, y, (unsigned char*)base64_decode(s).c_str(), 64);
    initCurveTwistEwards25519();
    q.assignPoint(x, y, *Ed_curves25519);
   // q.printPoint();
    unsigned char *test = enCodeCert(q, (char*)"Bob", (char*)"Tue Apr 17 17:24:41 2018");
    for(int i = 0; i < 32;i++) {
        printf("%02hhx", test[i]);
    }
}
