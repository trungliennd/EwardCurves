#include<stdio.h>

char* readLine(FILE *file) {
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    if ((read = getline(&line, &len, file)) == -1) return NULL;
    return line;
}

int compare(unsigned char *a, unsigned char *b, int size) {
    while(size-- > 0) {
        if ( *a != *b ) { return (*a < *b ) ? -1 : 1; }
        a++; b++;
    }
    return 0;
}
