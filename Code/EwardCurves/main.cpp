#include "ImplicitCertificate.h"
int main() {
 /* mpz_t t,t1,rs,temp1,temp2;
  mpz_init(t);
  mpz_init(temp1);
  mpz_init(temp2);
  mpz_init(t1);
  mpz_init(rs);
  mpz_set_str(t1, "27742317777372353535851937790883648493", 10);
  mpz_ui_pow_ui(t, 2, 252);
  mpz_add(rs, t, t1);
  gmp_printf("\nrs is: %Zd\n",rs);
  unsigned char point[64];
  ellipticCurvePointToString(t1, rs, point,64);
  printf("\nrs is: ");
  for(int i = 0;i < 64;i++) {
    printf("%x",point[i]);
  }
  printf("\n");
  stringToEllipticCurvePoint(temp1, temp2, point, 64);
  gmp_printf("\ny  is: %Zd\n",temp2);*/
    //createPairKey_ku_vs_Ru((char*)"ca",(char*)"ca.pub");
  /* loadKey_new((char*)"key",(char*)"key.pub");  //test();
   unsigned char key_Ru[88];

   ellipticCurvePointToString(Ru.x_.i_, Ru.y_.i_, key_Ru, 64);
   char* u;
   char* v;
  // cert_Request((char*)"Alice",(unsigned char*)base64_encode(key_Ru, 64).c_str(), (char*)"request.cert");*/
  // create_certificate((char*)"request.cert",(char*)"ca.crt");
  struct cert certificate;
  loadCertificate(certificate, (char*)"ca.crt");
 // printf("time %s", certificate.time_expired);
  printCertificate(certificate, (char*)"ca1.crt");
 /* char test[88] = {"000c912130d0f576c1caa067c2faa223771d61739c0aa8471a7333004b4c4d4e"};
  unsigned char hashCode[32];
  char *it = test;
  for(int i = 0;i < 32;i++) {
        sscanf(test +(i*2), "%02hhx",&hashCode[i]);
  }
  printKey(hashCode, 32);*/
}
