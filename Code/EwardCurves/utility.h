#include<stdio.h>

char* readLine(FILE *file) {
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    if ((read = getline(&line, &len, file)) == -1) return NULL;
    return line;
}


 void str_copy(unsigned char des[], unsigned char src[], int len) {
        for(int i = 0;i < len;i++) {
            des[i] = src[i];
        }
        des[len] = '\0';
    }

void str_copy(char des[], char src[]) {
        int i = 0;
        while(src[i] != '\0') {
            des[i] = src[i];
            i++;
        }
        des[i] = '\0';
    }

void str_copy(unsigned char des[],unsigned char src[]) {

        int i = 0;
        while(src[i] != '\0') {
            des[i] = src[i];
            i++;
        }
        des[i] = '\0';
}


int compare(unsigned char *a, unsigned char *b, int size) {
    while(size-- > 0) {
        if ( *a != *b ) { return (*a < *b ) ? -1 : 1; }
        a++; b++;
    }
    return 0;
}
