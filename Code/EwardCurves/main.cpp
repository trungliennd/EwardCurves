#include "ImplicitCertificate.h"
using namespace Cryptography;

int main() {
    char time1[32];
    char time2[32];
    getTime(time1,time2,30);
    printf("\n%s",time1);
}
