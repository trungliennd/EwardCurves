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
