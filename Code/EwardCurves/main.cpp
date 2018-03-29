#include "ImplicitCertificate.h"

int main() {
  mpz_t t,t1,rs;
  mpz_init(t);
  mpz_init(t1);
  mpz_init(rs);
  mpz_set_str(t1, "27742317777372353535851937790883648493", 10);
  mpz_ui_pow_ui(t, 2, 252);
  mpz_add(rs, t, t1);
  gmp_printf("\nN is: %Zd",rs);
  hashModul((char*)"trungdq", t, 256, 253, sha256);

}
