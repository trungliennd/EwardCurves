#include <math.h>
#include "FinteFiledElement.h"
#include "base64.h"
#include <time.h>
#include <string.h>
using namespace Cryptography;

void sha256(char *string, unsigned char hash_code[32]);
void HashModul(char *string, mpz_t rs, unsigned int hash_bits, unsigned int modul_bits, void(*function)(char *string, char *out));
void stringToInteger(unsigned char decode[], mpz_t &num_decode, unsigned int bytes);
void cert_Request(char identity[], unsigned char key_Ru[], char *file_out);
void ellipticCurvePointToString(mpz_t& x, mpz_t& y, unsigned char string_point[], int bytes);
void stringToEllipticCurvePoint(mpz_t& x, mpz_t& y, unsigned char string_point[], int bytes);
void createPairKey_ku_vs_Ru(char* file_ku, char* file_Ru);
void calculate_r_or_du(mpz_t &rs_out, mpz_t e, mpz_t k, mpz_t r_or_d_ca);

ed25519::Point Ru;
ed25519::Point Pu;
ed25519::Point Qu;
ed25519::Point Qca;
ed25519::Point Qv;
mpz_t ku;
mpz_t du;
mpz_t kv;
mpz_t dv;
mpz_t k_ca;
mpz_t d_ca;
mpz_t r;

const char *year[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

struct cert {
    char identify[30];
    char time_created[30];
    char time_expired[30];
    unsigned char hashCode[32];
    unsigned char key[64]; // Pu
    unsigned char key_ca[64]; // Q_ca
    unsigned char r_key[32];
};


void copyKey(unsigned char *a,const char* b,int len) {
    for(int i =0 ;i < len;i++) {
        a[i] = b[i];
    }
}

int find_month(char *month) {
    for(int i = 0 ;i < 12;i++) {
        if(strcmp(year[i], month) == 0)
            return (i + 1);
    }
}

unsigned char* str_cat(unsigned char* src, unsigned char* dest) {
    int size = 0;
    int i,j;
    for(i = 0;;i++) {
        if(src[i] != '\0') size++;
        else break;
    }
    for(j = 0;;j++) {
        if(dest[j] != '\0') size++;
        else break;
    }
    unsigned char *temp = new unsigned char[size];
    for(int i1 = 0;i1 < i;i1++) {
        temp[i1] = src[i1];
    }
    for(int i2 = 0;i2 < j;i2++) {
        temp[i + i2] = dest[i2];
    }
    temp[size] = '\0';
    return temp;
}
void convertTime(char* time) {
    int i = 0;
    while(time[i] != '\0') {
        if(time[i] == ' ') {
            time[i] = '-';
        }
        i++;
    }
}

void recoverTime(char *time) {
    int i = 0;
    while(time[i] != '\0') {
        if(time[i] == '-') {
            time[i] = ' ';
        }
        i++;
    }
}

void getTime(char time_created[], char time_expired[], int days) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    char *created = asctime(timeinfo);
    str_copy(time_created, created);
    time_created[24] = '\0';
    //printf ( "Current local time and date: %s", time_created);
    struct tm *then_tm = timeinfo;
    then_tm->tm_mday += days;
    time_t thentime = mktime(then_tm);
    then_tm = localtime(&thentime);
    char *expired = asctime(then_tm);
    str_copy(time_expired, expired);
    time_expired[24] = '\0';
    // printf ( "Current local time and date: %s", asctime (then_tm) );
    return;
}

time_t getStructTime(char* time) {
    recoverTime(time);
    int day = 0, year = 0, month = 0, hour = 0, minute = 0, seconds = 0;
    char day_str[3], month_str[3];
    sscanf(time, "%s %s  %d %d:%d:%d %d", day_str,
                    month_str, &day, &hour, &minute, &seconds, &year);
    struct tm breakdown = {0};
    month = find_month(month_str);
    breakdown.tm_year = year - 1900; /* years since 1900 */
    breakdown.tm_mon = month - 1;
    breakdown.tm_mday = day;
    breakdown.tm_hour = hour;
    breakdown.tm_sec = seconds;
    breakdown.tm_min = minute;
    time_t result = 0;
    if ((result = mktime(&breakdown)) == (time_t)-1) {
        fprintf(stderr, "Time invalidate \n");
        return EXIT_FAILURE;
    }
    return result;
}


void str_inv_copy(unsigned char des[], unsigned char src[], int len) {
        for(int i = 0;i < len;i++) {
            des[len - i - 1] = src[i];
        }
        des[len] = '\0';
}

void sha256(char *string, unsigned char hash_code[32]) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash_code, &sha256);
}

// modul n = 2^252 + 27742317777372353535851937790883648493
void hashModul(char *string_hash, mpz_t &rs, unsigned int hash_bits, unsigned int modul_bits,
                                            void(*function)(char *string,unsigned char *out)) {
    unsigned char output[32];
    function(string_hash, output);
    unsigned char andBits[5] = {0xff, 0x7f, 0x3f, 0x1f, 0x0f};
    int num_bits = hash_bits - modul_bits;
    output[0] = ( output[0] & andBits[num_bits]);
    stringToInteger(output, rs, 32);
}

void hashModul(unsigned char string[32], mpz_t&rs, unsigned int hash_bits, unsigned int modul_bits) {
    unsigned char output[32];
    str_copy(output, string, 32);
    unsigned char andBits[5] = {0xff, 0x7f, 0x3f, 0x1f, 0x0f};
    int num_bits = hash_bits - modul_bits;
    output[0] = ( output[0] & andBits[num_bits]);
    stringToInteger(output, rs, 32);
}


void stringToInteger(unsigned char hash[], mpz_t &num_decode, unsigned int bytes) {
    char out[65];
    int i = 0;
    for(i = 0; i < bytes; i++){
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[64] = 0;
    mpz_set_str(num_decode,out, 16);
}

void savePairKey(mpz_t &key, ed25519::Point &pub_key, char *file_key, char *file_pubkey) {
    unsigned char ar_key[32];
    crypto_encode_ed225519_ClampC(ar_key, key, 32);
    unsigned char ar_pubkey[64];
    ellipticCurvePointToString(pub_key.x_.i_, pub_key.y_.i_, ar_pubkey, 64);
    FILE* out1 = fopen(file_key, "w");
    if(out1 == NULL) {
        printf("\nWrite secretKey Fail");
        exit(1);
    }else {
        string secret = base64_encode(ar_key,crypto_sign_ed25519_SECRETKEYBYTES);
        int len = secret.length();
        fprintf(out1,"---------------- SECERT KEY ----------------\n");
        fwrite(secret.c_str(),1,len,out1);
        fprintf(out1,"\n--------------------------------------------");
    }
    fclose(out1);
    FILE* out2 = fopen(file_pubkey, "w");
    if(out2 == NULL) {
        printf("\nWrite pubKey Fail");
        exit(1);
    }else {
        string pubkey = base64_encode(ar_pubkey,crypto_sign_ed25519_PUBLICKEYBYTES_D);
        int len = pubkey.length();
        fprintf(out2,"-------------------------------------- PUBLIC KEY --------------------------------------\n");
        fwrite(pubkey.c_str(),1,len,out2);
        fprintf(out2,"\n----------------------------------------------------------------------------------------");
    }
    fclose(out2);
}

void createPairKey_ku_vs_Ru(char* file_ku, char* file_Ru) {
    if(Ed_curves25519 == NULL) {
        initCurveTwistEwards25519();
    }
    mpz_init(ku);
    mpz_set_str(ku, "425638306587506704699731512122928355317925", 10);
   // randNumberSecretKey(ku);
   // gmp_printf("\nk_create is: %Zd",ku);
    unsigned char key_ku[32];
    crypto_encode_ed225519_ClampC(key_ku, ku, 32);
    ed25519::Point q;
    q.scalarMultiply(ku, Ed_curves25519->returnGx());
    unsigned char key_Ru[64];
    ellipticCurvePointToString(q.x_.i_, q.y_.i_, key_Ru, 64);
    FILE* out1 = fopen(file_ku, "w");
    if(out1 == NULL) {
        printf("\nWrite secretKey Fail");
        exit(1);
    }else {
        string secret = base64_encode(key_ku,crypto_sign_ed25519_SECRETKEYBYTES);
        int len = secret.length();
        fprintf(out1,"---------------- SECERT KEY ----------------\n");
        fwrite(secret.c_str(),1,len,out1);
        fprintf(out1,"\n--------------------------------------------");
    }
    fclose(out1);
    FILE* out2 = fopen(file_Ru, "w");
    if(out2 == NULL) {
        printf("\nWrite pubKey Fail");
        exit(1);
    }else {
        string pubkey = base64_encode(key_Ru,crypto_sign_ed25519_PUBLICKEYBYTES_D);
        int len = pubkey.length();
        fprintf(out2,"-------------------------------------- PUBLIC KEY --------------------------------------\n");
        fwrite(pubkey.c_str(),1,len,out2);
        fprintf(out2,"\n----------------------------------------------------------------------------------------");
    }
    fclose(out2);
}


void loadKey_new(char*file_ku, char*file_Ru) {
    // secret key
    if(file_ku != NULL) {
        FILE* readFile = fopen(file_ku, "r");
        if(readFile == NULL) {
            printf("\nCan't read secretKey");
            exit(EXIT_FAILURE);
        }else {
            unsigned char key_ku[BASE64_LEN];
            fread(key_ku,1,BASE64_LEN,readFile);
            fscanf(readFile,"%c",&key_ku[BASE64_LEN - 1]);
            fread(key_ku,1,BASE64_LEN,readFile);
            key_ku[BASE64_LEN] = '\0';
            string s((char*)key_ku);
            mpz_init(ku);
            crypto_decode_ed225519_ClampC((unsigned char*)base64_decode(s).c_str(), ku, 32);
        }
        fclose(readFile);
    }
    if(file_Ru != NULL) {
        FILE* readFile1 = fopen(file_Ru, "r");
        if(readFile1 == NULL) {
            printf("\nCan't read publicKey");
            exit(EXIT_FAILURE);
        }else {
            unsigned char pub[BASE64_LEN_D];
            fread(pub,1,BASE64_LEN_D,readFile1);
            fscanf(readFile1,"%c",&pub[BASE64_LEN_D - 1]);
            fread(pub,1,BASE64_LEN_D,readFile1);
            pub[BASE64_LEN_D] = '\0';
            string s((char*)pub);
            mpz_t x, y;
            mpz_init(x);
            mpz_init(y);
            stringToEllipticCurvePoint(x, y, (unsigned char*)base64_decode(s).c_str(), crypto_sign_ed25519_PUBLICKEYBYTES_D);
            if(Ed_curves25519 == NULL) {
                initCurveTwistEwards25519();
            }
            Ru.assignPoint(x, y, *Ed_curves25519);
        }
        fclose(readFile1);
    }
}

void loadKey_ca(char*file_k_ca, char*file_Q_ca) {
    // secret key
    if(file_k_ca != NULL) {
        FILE* readFile = fopen(file_k_ca, "r");
        if(readFile == NULL) {
            printf("\nCan't read secretKey");
            exit(EXIT_FAILURE);
        }else {
            unsigned char key_kca[BASE64_LEN];
            fread(key_kca,1,BASE64_LEN,readFile);
            fscanf(readFile,"%c",&key_kca[BASE64_LEN - 1]);
            fread(key_kca,1,BASE64_LEN,readFile);
            key_kca[BASE64_LEN] = '\0';
            string s((char*)key_kca);
            mpz_init(d_ca);
            crypto_decode_ed225519_ClampC((unsigned char*)base64_decode(s).c_str(), d_ca, 32);
        }
        fclose(readFile);
    }
    if(file_Q_ca != NULL) {
        FILE* readFile1 = fopen(file_Q_ca, "r");
        if(readFile1 == NULL) {
            printf("\nCan't read publicKey");
            exit(EXIT_FAILURE);
        }else {
            unsigned char pub[BASE64_LEN_D];
            fread(pub,1,BASE64_LEN_D,readFile1);
            fscanf(readFile1,"%c",&pub[BASE64_LEN_D - 1]);
            fread(pub,1,BASE64_LEN_D,readFile1);
            pub[BASE64_LEN_D] = '\0';
            string s((char*)pub);
            mpz_t x, y;
            mpz_init(x);
            mpz_init(y);
            stringToEllipticCurvePoint(x, y, (unsigned char*)base64_decode(s).c_str(), crypto_sign_ed25519_PUBLICKEYBYTES_D);
            if(Ed_curves25519 == NULL) {
                initCurveTwistEwards25519();
            }
            Qca.assignPoint(x, y, *Ed_curves25519);
        }
        fclose(readFile1);
    }
}

void cert_Request(char identity[], unsigned char key_Ru[], char *file_out) {
    FILE* out = fopen(file_out, "w");
    fprintf(out, "{\n");
    fprintf(out, "\"Identity\": \"");
    int i = 0;
    while(identity[i] != '\0') {
        fprintf(out,"%c",identity[i]);
        i++;
    }
    fprintf(out, "\"\n");
    fprintf(out, "\"Key\": \"");
    i = 0;
    while(key_Ru[i] != '\0') {
        fprintf(out,"%c",key_Ru[i]);
        i++;
    }
    fprintf(out, "\"\n}\n");
    fclose(out);
}



void createPu(ed25519::Point &Ru) {
    if(Ed_curves25519 == NULL) {
        initCurveTwistEwards25519();
    }
    mpz_init(k_ca);
    mpz_set_str(k_ca, "9045783334", 10);
   // randNumberSecretKey(k_ca);
  //  gmp_printf("\nK1 is: %Zd",k_ca);
    ed25519::Point q;
    q.scalarMultiply(k_ca, Ed_curves25519->returnGx());
    q.add(Ru.x_, Ru.y_, q.x_, q.y_);
    Pu.assignPoint(q);
}

unsigned char* enCodeCert(ed25519::Point &Pu, char identify[], char time[]) {
    unsigned char temp1[64],*temp;
    ellipticCurvePointToString(Pu.x_.i_, Pu.y_.i_, temp1, 64);
    temp = (unsigned char*)str_cat((unsigned char*)identify, (unsigned char*)time);
    temp = str_cat(temp, temp1);
    int size = 0;
    unsigned char *rs = new unsigned char[32];
    sha256((char*)temp, rs);
    return rs;
}

void convert(char *line) {
    int i = 0;
    if(line == NULL) return;
    bool check = true;
    while(line[i] != '\0') {
        if(line[i] == '"') {
            line[i] = ' ';
        }
        if(line[i] == ':' && check) {
            check = false;
            line[i] = ' ';
        }
        i++;
    }
}

void printCertificate(struct cert &certificate, char *file_out) {
    FILE *out = fopen(file_out, "w");
    fprintf(out, "{\n");
    fprintf(out, "\"Identity\": \"");
    fprintf(out, "%s\"\n", certificate.identify);
    fprintf(out, "\"Key\": \"");
    fprintf(out, "%s\"\n", base64_encode(certificate.key, 64).c_str());
    fprintf(out, "\"Public_key_ca\": \"");
    fprintf(out, "%s\"\n", base64_encode(certificate.key_ca, 64).c_str());
    fprintf(out, "\"Time_created\": \"");
    convertTime(certificate.time_created);
    fprintf(out, "%s\"\n", certificate.time_created);
    fprintf(out, "\"Time_expired\": \"");
    convertTime(certificate.time_expired);
    fprintf(out, "%s\"\n", certificate.time_expired);
    fprintf(out, "\"Hash_code\": \"");
    for(int i= 0;i < 32;i++)
        fprintf(out, "%02hhx",certificate.hashCode[i]);
    fprintf(out, "\"\n");
    fprintf(out, "\"R\": \"");
    fprintf(out, "%s\"", base64_encode(certificate.r_key, 32).c_str());
    fprintf(out,"\n}\n");
    fclose(out);
}

void loadCertificate(struct cert &certificate, char* file_in) {
    FILE* in = fopen(file_in, "r");
    char *line = readLine(in);
    while(!feof(in) && line != NULL) {
        if((strcmp(line,(char*)"{\n") == 0) || (strcmp(line, (char*)"}\n") == 0)) {
            line = readLine(in);
            continue;
        }
        convert(line);
        char s1[30];
        sscanf(line, "%s",s1);
        if(strcmp(s1, (char*)"Identity") == 0) {
            char s2[30];
            sscanf(line, "%s %s",s1,s2);
            str_copy(certificate.identify, s2);
        }
        if(strcmp(s1, (char*)"Time_created") == 0) {
            char s2[30];
            sscanf(line, "%s %s",s1,s2);
            recoverTime(s2);
            str_copy(certificate.time_created, s2);
        }
        if(strcmp(s1, (char*)"Time_expired") == 0){
            char s2[30];
            sscanf(line, "%s %s",s1,s2);
            recoverTime(s2);
            str_copy(certificate.time_expired, s2);
        }
        if(strcmp(s1, (char*)"Key") == 0) {
            char s2[88];
            sscanf(line, "%s %s",s1,s2);
            string s((char*)s2);
        //    printf("\nbase64 is: %s\n", s2);
       //     printKey((unsigned char*)base64_decode(s).c_str(), 64);
            str_copy(certificate.key, (unsigned char*)base64_decode(s).c_str(),64);
        //    printf("\nbase64 is: %s\n", base64_encode(certificate.key, 64).c_str());
        }
        if(strcmp(s1, (char*)"Public_key_ca") == 0) {
            char s2[88];
            sscanf(line, "%s %s",s1,s2);
            string s((char*)s2);
            str_copy(certificate.key_ca, (unsigned char*)base64_decode(s).c_str(),64);
        }
        if(strcmp(s1, (char*)"Hash_code") == 0) {
            char s2[64];
            sscanf(line, "%s %s",s1,s2);
            for(int i = 0;i < 32;i++) {
                sscanf(s2 + (i*2), "%02hhx",&certificate.hashCode[i]);
            }
        }
        if(strcmp(s1, (char*)"R") == 0) {
            char s2[44];
            sscanf(line, "%s %s",s1,s2);
            string s((char*)s2);
            str_copy(certificate.r_key, (unsigned char*)base64_decode(s).c_str(),32);
        }
        line = readLine(in);
    }
    fclose(in);
    return;
}

void create_certificate(char* file_in, char*file_out) {
    struct cert temp;
    FILE* in = fopen(file_in, "r");
    char *line = NULL;
    unsigned char key_Ru[88];
    while(!feof(in)) {
        line = readLine(in);
        if(line == NULL){
            break;
        }
        if((strcmp(line,(char*)"{\n") == 0) || (strcmp(line, (char*)"}\n") == 0)) continue;
        char s1[30],s2[256];
        convert(line);
        sscanf(line," %s   %s ",s1, s2);
        if(strcmp(s1, (char*)"Identity") == 0) {
            str_copy(temp.identify, s2);  // 1
        }else if(strcmp(s1, (char*)"Key") == 0) {
            str_copy(key_Ru, (unsigned char*)s2, 88);
        }
    }
    if(line != NULL) free(line);
    fclose(in);
    if(Ed_curves25519 == NULL) {
        initCurveTwistEwards25519();
    }
    mpz_t x,y,e;
    mpz_init(x);
    mpz_init(y);
    mpz_init(e);
    string s((char*)key_Ru);
    stringToEllipticCurvePoint(x, y, (unsigned char*)base64_decode(s).c_str(), 64);
    Ru.assignPoint(x, y, *Ed_curves25519);
    createPu(Ru);
    gmp_printf("\nk_ca is: %Zd\n",k_ca);
    printf("\nRu is: \n");
    Ru.printPoint();
    printf("\nPu is: \n");
    Pu.printPoint();
    getTime(temp.time_created, temp.time_expired, 30);// 5, 6
    unsigned char *string_hash = enCodeCert(Pu, temp.identify, temp.time_created);
    str_copy(temp.hashCode, string_hash, 32); // 4
    hashModul(string_hash, e, 256, 255);
    gmp_printf("\ne is: %Zd\n",e);
    loadKey_ca((char*)"ca",(char*)"ca.pub");
    calculate_r_or_du(r, e, k_ca, d_ca);
    gmp_printf("\nr is: %Zd\n",r);
    gmp_printf("\nd_ca is: %Zd\n",d_ca);
    gmp_printf("\n r is: %Zd",r);
    ellipticCurvePointToString(Pu.x_.i_, Pu.y_.i_, temp.key, 64);  // 2
    ellipticCurvePointToString(Qca.x_.i_, Qca.y_.i_, temp.key_ca, 64); // 3
    crypto_encode_ed225519_ClampC(temp.r_key, r, 32);
  //  printKey(temp.r_key,32);
    printCertificate(temp, file_out);
    return;
}



void calculate_r_or_du(mpz_t &rs_out, mpz_t e, mpz_t k, mpz_t r_or_d_ca) {
    if(Ed_curves25519 == NULL) {
        initCurveTwistEwards25519();
    }
    mpz_init(rs_out);
    ffe_t f_e(e, Ed_curves25519->P), f_k(k, Ed_curves25519->P), f_r_or_dca(r_or_d_ca, Ed_curves25519->P),rs;
    rs.mulFiniteFieldElement(f_e, f_k);
    rs.addFiniteFieldElement(rs, f_r_or_dca);
    mpz_set(rs_out, rs.i_);
}


void calculate_Qu(mpz_t e, ed25519::Point &Pu, ed25519::Point &Q_ca) {
    if(Ed_curves25519 == NULL) {
        initCurveTwistEwards25519();
    }
    Qu.scalarMultiply(e, Pu);
    Qu.add(Qu.x_, Qu.y_, Q_ca.x_, Q_ca.y_);
}



void ellipticCurvePointToString(mpz_t& x, mpz_t& y,unsigned char string_point[], int bytes) {
    unsigned char point_x[32];
    crypto_encode_ed225519_ClampC(point_x, x, 32);
    unsigned char point_y[32];
    crypto_encode_ed225519_ClampC(point_y, y, 32);
    int index = bytes/2;
    for(int i=0;i < index;i++) {
       string_point[i] = point_x[i];
       string_point[index + i] = point_y[i];
    }
    string_point[bytes] = '\0';
}

void stringToEllipticCurvePoint(mpz_t& x, mpz_t& y, unsigned char string_point[], int bytes) {
    int index = bytes/2;
    unsigned char point_x[32];
    unsigned char point_y[32];
    for(int i = 0;i < index;i++) {
        point_x[i] = string_point[i];
        point_y[i] = string_point[index + i];
    }
    crypto_decode_ed225519_ClampC(point_x, x, 32);
    crypto_decode_ed225519_ClampC(point_y, y, 32);
}


bool checkCertificate(struct cert& certificate) {
    time_t time1 = getStructTime(certificate.time_expired);
    time_t time2;
    time(&time2);
    double diff = difftime(time1, time2);
    if(diff < 0) return false;
    mpz_t x,y;
    mpz_init(x);
    mpz_init(y);
    stringToEllipticCurvePoint(x, y, certificate.key, 64);
    if(Ed_curves25519 == NULL) initCurveTwistEwards25519();
    Pu.assignPoint(x, y, *Ed_curves25519);
    unsigned char *string_hash = enCodeCert(Pu, certificate.identify, certificate.time_created);
    if(compare(string_hash, certificate.hashCode , 32) != 0) return false;
    return true;
}

bool checkKeyExtract(mpz_t &d_u, ed25519::Point &Q_u) {
    if(Ed_curves25519 == NULL) initCurveTwistEwards25519();
   // gmp_printf("%Zd",d_u);
    ed25519::Point temp;
    temp.scalarMultiply(d_u, Ed_curves25519->returnGx());
 //   temp.printPoint();
  //  Q_u.printPoint();
    if(!temp.comparePoint(Q_u)) {
        return false;
    }
    return true;
}

void recoverQ_u_vs_du(struct cert& certificate, char *file_ku,char *file_du, char *file_Qu) {
    bool check = checkCertificate(certificate);
    if(!check) {
        printf("\nCertificate Invalid???\n");
        exit(1);
    }
    mpz_t e;
    mpz_init(e);
    hashModul(certificate.hashCode,e, 256, 255);
    gmp_printf("\ne is: %Zd\n",e);
    mpz_init(du);
    loadKey_new(file_ku, NULL);
    gmp_printf("\nku is: %Zd\n",ku);
    mpz_init(r);
    crypto_decode_ed225519_ClampC(certificate.r_key, r, 32);
    gmp_printf("\nr is: %Zd\n",r);
    calculate_r_or_du(du, e, ku, r);
    gmp_printf("\ndu is: %Zd\n",du);
    mpz_t x,y;
    mpz_init(x);
    mpz_init(y);
    stringToEllipticCurvePoint(x, y, certificate.key_ca, 64);
    if(Ed_curves25519 == NULL) initCurveTwistEwards25519();
    Qca.assignPoint(x, y, *Ed_curves25519);
    printf("\nQca: ");
    Qca.printPoint();
    printf("\nPu: ");
    Pu.printPoint();
    if(Ed_curves25519->checkPoint(Pu.x_, Pu.y_)) {
        printf("\ncase11\n");
    }
    calculate_Qu(e, Pu, Qca);
    printf("\nQu: ");
    Qu.printPoint();
    if(Ed_curves25519->checkPoint(Qu.x_, Qu.y_)) {
        printf("\ncase12\n");
    }
    if(!checkKeyExtract(du, Qu)) {
        printf("\nCertificate Invalid???\n");
        exit(1);
    }
    savePairKey(du, Qu, file_du, file_Qu);
}
