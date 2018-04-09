#include<stdio.h>

char* readLine(FILE *file) {
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    if ((read = getline(&line, &len, file)) == -1) return NULL;
    return line;
}
