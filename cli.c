#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

enum {
    START,
    STOP,
    SHOW_COUNT,
    SELECT,
    STAT
};

struct message_t {
    char type;
    uint8_t param;
    char str[20];
};

char command[20];
char daemon_state = 0;

struct message_t message;
int longIndex;
static const char *optString = "she:pS:t:?";

static const struct option longOpts[] = {
    { "start", no_argument, NULL, 's'},
    { "stop", no_argument, NULL, 'p'},
    { "show_count", required_argument, NULL, 't'},
    { "select_iface", required_argument, NULL, 'e'},
    { "stat", required_argument, NULL,'S'},
    { "help", no_argument, NULL, 'h'}
};

int main(int argc, char *argv[]) {
    int opt = 0;
    int sock;
    struct sockaddr_in addr;
    int num_byte = 0;

    while (opt != -1) {
    opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
        switch(opt) {
            case '?':
            case 'h':
                printf("cli --start - start sniffer\n");
                printf("cli --stop - stop sniffer\n");
                printf("cli -e [iface] - select interface\n");
                printf("cli -t [i] - show statistic from pointed ip\n");
                printf("cli -S - show statistic from pointed interface \n");
                break;
            case 's'://start
                message.type = START;
                break;
            case 'p'://stop
                message.type = STOP;
                break;
            case 'e':
                message.type = SELECT;
                strcpy(message.str, optarg); 
                break;
            case 't':
                message.type = SHOW_COUNT;
                strcpy(message.str, optarg);
                break;
            case 'S':
                message.type = STAT;
                strcpy(message.str, optarg); 
                break;
                
            default:
                break;

        }
    }
    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(3425);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
         perror("conect");
         return 0;
    }
    num_byte = send(sock, &message, sizeof(message), 0);
    close(sock);

    return 0;
} 

