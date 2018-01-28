#include <NTL/ZZ.h>
#include <iostream>

using namespace std;
using namespace NTL;


long witness(const ZZ& n, const ZZ& x)
{
   ZZ m, y, z;
   long j, k;

   if (x == 0) return 0;

   // compute m, k such that n-1 = 2^k * m, m odd:

   k = 1;
   m = n/2;
   while (m % 2 == 0) {
      k++;
      m /= 2;
   }

   z = PowerMod(x, m, n); // z = x^m % n
   if (z == 1) return 0;

   j = 0;
   do {
      y = z;
      z = (y*y) % n;
      j++;
   } while (j < k && z != 1);

   return z != 1 || y != n-1;
}


long isPrime(const ZZ& n, long t)
{
   if (n <= 1) return 0;

   // first, perform trial division by primes up to 2000

   PrimeSeq s;  // a class for quickly generating primes in sequence
   long p;

   p = s.next();  // first prime is always 2
   while (p && p < 2000) {
      if ((n % p) == 0) return (n == p);
      p = s.next();
   }

   // second, perform t Miller-Rabin tests

   ZZ x;
   long i;

   for (i = 0; i < t; i++) {
      x = RandomBnd(n); // random number between 0 and n-1

      if (witness(n, x))
         return 0;
   }

   return 1;
}

class RSA {

    private:
        ZZ p,q,n;
        ZZ e,d;

    public:
    RSA(const ZZ&a,const ZZ&b){
        this->n = (p-1)*(q-1);
    }

    void SelectTwoPrime() {

    }

    ZZ extended_gcd(const ZZ&a,const ZZ&b) {
        ZZ s,t,r,old_s,old_t,old_r,temp1;
        s = ZZ(0);
        t = ZZ(1);
        r = b;
        old_s = ZZ(1);
        old_t = ZZ(0);
        old_r = a;

        while(r != 0) {

            ZZ quotient = old_r/r;
            temp1 = old_r;
            old_r = r;
            r = temp1 - (quotient*r);
            temp1 = old_s;
            old_s = s;
            s = temp1 - (quotient*s);
            temp1 = old_t;
            old_t = t;
            t = temp1 - (quotient*t);
            }
        return old_r;
    }



};

int main() {
    ZZ q(45),p(75);
    RSA a(p,q);
    ZZ b = a.extended_gcd(q,p);
    cout << b;
}
