#include "EwardCurves.h"

int main() {
    printf("\nHello World!!\n");
    //createPublicKeyAndSecretKey((char*)"Alice", (char*)"Alice.pub");
    loadKey((char*)"Alice",(char*)"Alice.pub");
  //  encrypto_messages((char*)"messages.txt", (char*)"cipher_text.txt");
    decrypto_messages((char*)"cipher_text.txt",(char*)"messages1.txt");
}
