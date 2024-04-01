#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Rand Port Gen By Gcezp. Use This To Get Your Cnc Port
// How To Compile: gcc randport.c -o rand -pthread
// Usage: ./rand

int main(void) 
{
    const int port_max = 65535;
    srand((unsigned )time(NULL));
    printf("\x1b[1;34m%d \x1b[1;37mIs The Generated Port\x1b[0m\n", rand() % port_max);
    return 0;
}