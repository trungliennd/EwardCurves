#include "ImplicitCertificate.h"
using namespace Cryptography;

int main() {
 //   createPairKey_ku_vs_Ru((char*)"Bob",(char*)"Bob.pub");
  /*  loadKey_new((char*)"Bob",(char*)"Bob.pub");
    unsigned char key[64];
    ellipticCurvePointToString(Ru.x_.i_, Ru.y_.i_, key, 64);
    cert_Request((char*)"Bob",(unsigned char*)base64_encode(key,64).c_str(), (char*)"cert_bob.crt");*/
 //   create_certificate((char*)"cert_bob.crt",(char*)"certificate_bob.crt");
    struct cert certificate;
    loadCertificate(certificate, (char*)"certificate_bob.crt");
   // printCertificate(certificate,(char*)"cc.crt");
    recoverQ_u_vs_du(certificate, (char*)"Bob", (char*)"Bob_s",(char*)"Bob_s.pub");

}
