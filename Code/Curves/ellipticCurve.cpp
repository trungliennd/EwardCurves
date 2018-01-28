#include "FinteFiledElement.h"
#include <iostream>
#include <vector>
#include <iomanip>
#include <ostream>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <math.h>
#include <sstream>
#include <NTL/ZZ.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>


using namespace std;
using namespace Cryptography;
using namespace NTL;


FILE *readFile;
FILE *writeFile;

struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];
	unsigned int num;
	unsigned char ecount[AES_BLOCK_SIZE];
};

struct ctr_state state;
AES_KEY key;
unsigned char iv[AES_BLOCK_SIZE];


int init_ctr(struct ctr_state *state,const unsigned char iv[16]) {
            state->num = 0;
            memset(state->ecount,0,AES_BLOCK_SIZE);
            // initialize counter in ivec to 0
            memset(state->ivec + 8,0,8);
            // Copy IV into 'ivec'
            memcpy(state->ivec,iv,8);
}

void enCryptionMessage(char *read,char *write,const unsigned char* enc_key) {

    if(!RAND_bytes(iv,AES_BLOCK_SIZE)) {
        cout << "Could not create random bytes." << endl;
        exit(1);
    }

    readFile = fopen(read,"rb");
    writeFile = fopen(write,"wb");

    if(readFile == NULL) {
        cout << "Read file is null" << endl;
        exit(1);
    }

    if(write == NULL) {
        cout << "Write file is null" << endl;
        exit(1);
    }


	fwrite(iv, 1, 8, writeFile); // IV bytes 1 - 8
    fwrite("\0\0\0\0\0\0\0\0", 1, 8, writeFile); // Fill the last 4 with null bytes 9 - 16

    if(AES_set_encrypt_key(enc_key,128,&key) < 0) {
        cout << "Could not set encryption key" << endl;
        exit(1);
    }

    init_ctr(&state,iv);
    // ma hoa 16 bytes va viet ra output
    int bytes_read,bytes_written;
    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];
    while(1) {
        bytes_read = fread(indata,1,AES_BLOCK_SIZE,readFile);
        AES_ctr128_encrypt(indata,outdata,bytes_read,&key,state.ivec,state.ecount,&state.num);
        bytes_written = fwrite(outdata,1,bytes_read,writeFile);

        if(bytes_read < AES_BLOCK_SIZE) {
            break;
        }
    }
    fclose(readFile);
    fclose(writeFile);
}

void deCryptionMessage(char *read,char *write,const unsigned char *enc_key) {
    readFile = fopen(read,"rb");
    writeFile = fopen(write,"wb");

    if(readFile == NULL) {
        cout << "Read File is null" << endl;
        exit(1);
    }

    if(writeFile == NULL) {
        cout << "Write File is null" << endl;
        exit(1);
    }

    fread(iv,1, AES_BLOCK_SIZE,readFile);
    if(AES_set_encrypt_key(enc_key,128,&key) < 0) {
        cout << "Could not set decryption key" << endl;
        exit(1);
    }
    init_ctr(&state,iv);
    int bytes_read,bytes_written;
    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];
    while(1) {
        bytes_read = fread(indata,1,AES_BLOCK_SIZE,readFile);
        AES_ctr128_encrypt(indata,outdata,bytes_read,&key,state.ivec,state.ecount,&state.num);

        bytes_written = fwrite(outdata,1,bytes_read,writeFile);
        if(bytes_read < AES_BLOCK_SIZE) {
            break;
        }
    }

}

string sha256(const string str) {

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256,str.c_str(),str.size());
    SHA256_Final(hash,&sha256);
    stringstream ss;
    for(int i = 0;i < SHA256_DIGEST_LENGTH;i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

unsigned char* Key(string k){
    unsigned char* key = new unsigned char[k.size() + 1];
    strcpy((char *)key,k.c_str());
}

string zToString(const ZZ& a) {
    stringstream buffer;
    buffer << a;
    return buffer.str();
}


int main() {
    // Du lieu dau vao duong cong  y^2 = x^3 + ax + b;
    string p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001";
    string a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE";
    string b = "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4";
    string s = "BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5";
    string gx = "02B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21";
    string n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D";
    string h = "01";

    // convert du lieu ve so nguyen lon ZZ
    ZZ P = convertToDecnum(p);
    ZZ A = convertToDecnum(a);
    ZZ B = convertToDecnum(b);
    ZZ S = convertToDecnum(s);
    ZZ Gx = convertToDecnum(gx);
    ZZ N = convertToDecnum(n);
    ZZ H = convertToDecnum(h);

    cout << "\n Protocol Diffe Hellman on Curve elliptic\n=======================================================\n\n";

    typedef EllipticCurve ec_t;
    ec_t myEllipticCurve(A,B,P);
    ec_t::Point G = myEllipticCurve.ReturnPoint(Gx);
    // Alice
    // 1, chon ngau nhien dA from 1 to p-1
    ZZ da = RandomBnd(P);
    ec_t::Point Pa = da*G; // public key
    cout << "Alice's public key Pa = " << Pa << endl;
    cout << endl;
    // Bob
    // chon ngau nhien dB from 1 to p-1
    ZZ db = RandomBnd(P);
    ec_t::Point Pb = db*G;
    cout << "Bob's public key Pb = " << Pb << endl;
    cout << endl;
    // Alice encryption message send to Bob (use public key of Bob)
    ec_t::Point PkA = da*Pb;
    //cout << "Private key is: " << PkA.x() << endl;
    string s1 = sha256(zToString(PkA.x().i()));
    unsigned char* P1Key = Key(s1);
    cout << "Private key is(Alice): " << s << endl;
    enCryptionMessage("encme.txt","encme.enc",P1Key);
    cout << endl;
    // Bob decryption message of Alice (use public key of Alice)
    ec_t::Point PkB = db*Pa;
    string s2 = sha256(zToString(PkB.x().i()));
    unsigned char* P2Key = Key(s2);
    cout << "Private key is(Bob): " << s << endl;
    deCryptionMessage("encme.enc","unencme1.txt",P2Key);
    cout << endl;

}
