#include "ImplicitCertificate.h"
using namespace Cryptography;

int main() {

  /*  loadKey_new((char*)"Bob",(char*)"Bob.pub");
    unsigned char key[64];
    ellipticCurvePointToString(Ru.x_.i_, Ru.y_.i_, key, 64);
    cert_Request((char*)"Bob",(unsigned char*)base64_encode(key,64).c_str(), (char*)"cert_bob.crt");*/
  //  create_certificate((char*)"cert_bob.crt",(char*)"certificate_bob.crt");
//    struct cert certificate;
 //   loadCertificate(certificate, (char*)"certificate_bob.crt");
   // printCertificate(certificate,(char*)"cc.crt");
  //  checkCertificate(certificate);
    //recoverQ_u_vs_du(certificate, (char*)"Bob", (char*)"Bob_s",(char*)"Bob_s.pub");
  // loadKey_ca((char*)"ca",(char*)"ca.pub");
   //checkKeyExtract(d_ca, Qca);
   unsigned char key[32];
   mpz_t x;
   mpz_init(x);
   mpz_set_str(x,(char*)"57894277771593319327455909206843211030042148144927926526749402028229175279635",10);
   crypto_encode_ed225519_ClampC(key, x, 32);
   printKey(key,32);
}
