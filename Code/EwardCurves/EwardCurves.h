#include <string.h>

char *strrev(char *str){
    char c, *front, *back;

    if(!str || !*str)
        return str;
    for(front=str,back=str+strlen(str)-1;front < back;front++,back--){
        c=*front;*front=*back;*back=c;
    }
    return str;
}


char *itoa(int v, char *buff, int radix_base){
    static char table[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char *p=buff;
    unsigned int n = (v < 0 && radix_base == 10)? -v : (unsigned int) v;
    while(n>=radix_base){
        *p++=table[n%radix_base];
        n/=radix_base;
    }
    *p++=table[n];
    if(v < 0 && radix_base == 10) *p++='-';
    *p='\0';
    return strrev(buff);
}


 /*  unsigned long randomSeed() {
        bool check = true;
        unsigned long rand1,rand2;
        while(check) {
            time_t t1;
            srand((unsigned)time(&t1));
            rand1 = abs(rand());
            time_t t2;
            srand((unsigned)time(&t2));
            rand2 = abs(rand());
            if(rand1 == rand2) continue;
            check = false;
        }
        rand1 = rand1 << (sizeof(int) * 8);
        unsigned long randRS = (rand1 | rand2);
        return randRS;
    } */

   /* void randomNumber(mpz_t rs, int bits) {
            unsigned long seed = randomSeed();
            gmp_randstate_t r_state;
            mpz_init(rs);
            gmp_randinit_default(r_state);
            gmp_randseed_ui(r_state, seed);
            mpz_urandomb(rs,r_state,bits);
            gmp_randclear(r_state);
    }*/
