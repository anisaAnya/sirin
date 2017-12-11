#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <errno.h>
#include <signal.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include "rbtree.h"
#include <fcntl.h>

#define PROMISC_MODE_ON 1
#define PROMISC_MODE_OFF 0

enum {
    START,
    STOP,
    SHOW_COUNT,
    SELECT,
    STAT
};

struct ifparam {
    __u32 ip;
    __u32 mask;
    int mtu;
    int index;
} ifp;

struct message {
    char type;
    uint8_t param;
    char str[20];
} message;

struct linked_list {
    unsigned int ip;
    unsigned int count;
    struct linked_list *next;
};

#define BUF_SIZE 70000

__u8 buff[BUF_SIZE];
int a = 0; 
char sniffer_state = STOP;
extern t_rbnode *root_rbtree;
struct linked_list *first_element;
char current_iface[200];
int eth0_if;

static int add_to_list(unsigned int ip, unsigned int count) {
    struct linked_list *element;

    element = malloc(sizeof(struct linked_list));

    if (!element) {
        printf("Can't alloc memory");
        return -1;
    }
    memset(element, 0, sizeof(struct linked_list));
    element->ip = ip;
    element->count = count;
    element->next = first_element;
    first_element = element;
}

static void update_counter(t_key ip, unsigned int count) {
    t_value value;
    value = get_key(root_rbtree, ip);
    if (value == 0) {
        add_to_list(ip, count);
    }
    value += count;
    insert(ip, value);
}

static int save_data(char *str) {
    struct linked_list *element;
    int file_desc;
    char file_name[200];

    if (!strlen(str)) {
        return -1;
    }
    sprintf(file_name, "log_%s.txt", str);
    file_desc = open(file_name, O_RDWR | O_CREAT);
    if (file_desc < 0) {
        printf("cant' open file");
        return -1;
    }
    element = first_element;
    first_element = NULL;
    while (element && element->next) {
        element->count = get_key(root_rbtree, element->ip);
        insert(element->ip, 0);
        write(file_desc, element, sizeof(struct linked_list));
        //printf("WRITE:ip = %x, count = %d\n", element->ip, element->count);
        free(element);
        element = element->next;
    }
    close(file_desc);

    return 0;
}

static void free_mem() {
    struct linked_list *element;

    element = first_element;
    first_element = NULL;
    while (element && element->next) {
        insert(element->ip, 0);
        free(element);
        element = element->next;
    }
}

static int read_data(char *str) {
    struct linked_list element;
    int file_desc;
    char file_name[200];

    if (!strlen(str)) {
        printf("%s:ERR:Choose iface\n", __func__);
        return -1;
    }
    sprintf(file_name, "log_%s.txt", str);
    first_element = malloc(sizeof(struct linked_list));
    if (!first_element) {
        printf("%s:memory allocation error\n", __func__);
    }
    memset(first_element, 0, sizeof(struct linked_list));

    file_desc = open(file_name, O_RDONLY);
    if (file_desc < 0) {
        printf("cant' open file. So it's first start\n");
    }
    while (read(file_desc, &element, sizeof(struct linked_list)) ==
                sizeof(struct linked_list)) {
        update_counter(element.ip, element.count);
        //printf("READ:ip = %x, count = %d\n", element.ip, element.count);
    }
    close(file_desc);

    return 0;
}

static int show_stat(char *iface) {
    struct linked_list *element;
    int a;
    unsigned char b1, b2, b3, b4;

    if (sniffer_state != STOP) {
        printf("ERR:stop sniffer first");
    }

    read_data(iface);
    element = first_element;
    while (element && element->next){
        a = element->ip;
        b1 = a&0xFF;
        b2 = (a>>8)&0xFF;
        b3 = (a>>16)&0xFF;
        b4 = (a>>24)&0xFF;
        printf("ip = %3d.%3d.%3d.%3d, count = %8d\n", b1, b2, b3, b4, element->count);
        element = element->next;
    }
    free_mem();
    return 0;
}

static unsigned int aton (char *str) {
    int len;
    unsigned char c[4];
    unsigned int n_ip;
    char str2[20];
    char *ip;

    strcpy(str2, str);
    ip = str2;
    len = strlen(ip);
    for (int i = 0; i < 11; i++) {
        if (ip[i] == '.') {
            ip[i] = 0;
        }
    }
    for (int j = 0; j<4;j++) {
        len = strlen(ip);
        c[j] = atoi(ip);
        ip += (len + 1);
    }
    n_ip = c[3];
    n_ip = n_ip <<8;
    n_ip += c[2];
    n_ip = n_ip <<8;
    n_ip += c[1];
    n_ip = n_ip <<8;
    n_ip += c[0];
    return n_ip;
}

static int show_count(char *ip) {
    if (!current_iface) {
        printf("ERR: Select iface first");
        return -1;
    }
    printf("ip = %s\n", ip);
    read_data(current_iface);
    printf("ip = n_ip = %s count = %d\n", ip, get_key(root_rbtree, aton(ip)));
    free_mem();
}

static int getifconf(__u8 *intf, struct ifparam *ifp, int mode) {
    int fd;
    struct sockaddr_in s;
    struct ifreq ifr; // см. <linux/if.h>

    memset((void *)&ifr, 0, sizeof(struct ifreq));
    if((fd = socket(AF_INET,SOCK_DGRAM,0)) < 0) return (-1);
    sprintf(ifr.ifr_name,"%s",intf);
    if(ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        return -1;
    }
    memset((void *)&s, 0, sizeof(struct sockaddr_in));
    memcpy((void *)&s, (void *)&ifr.ifr_addr, sizeof(struct sockaddr));
    memcpy((void *)&ifp->ip, (void *)&s.sin_addr.s_addr, sizeof(__u32));

    if(ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK");
        return -1;
    }
    memset((void *)&s, 0, sizeof(struct sockaddr_in));
    memcpy((void *)&s, (void *)&ifr.ifr_netmask, sizeof(struct sockaddr));
    memcpy((void *)&ifp->mask, (void *)&s.sin_addr.s_addr, sizeof(u_long));

    if(ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
        perror("ioctl SIOCGIFMTU");
        return -1;
    }
    ifp->mtu = ifr.ifr_mtu;

    if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        return -1;
    }
    ifp->index = ifr.ifr_ifindex;

    if(ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(fd);
        return -1;
    }

    if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(fd);
        return (-1);
    }

    return 0;
}

static int getsock_recv(int index)
{
    int sd;
    struct sockaddr_ll s_ll;

    sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sd < 0) return -1;
    memset((void *)&s_ll, 0, sizeof(struct sockaddr_ll));

    s_ll.sll_family = PF_PACKET; // тип сокета
    s_ll.sll_protocol = htons(ETH_P_ALL); // тип принимаемого протокола
    s_ll.sll_ifindex = index; // индекс сетевого интерфейса

    if(bind(sd, (struct sockaddr *)&s_ll, sizeof(struct sockaddr_ll)) < 0) {
    close(sd);
    return -1;
    }

    return sd;
}

static void *listen_thread(void *args) {
    int sock, listener;
    struct sockaddr_in addr;
    int bytes_read;
    int ret;
 
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        return NULL;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(3425);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return NULL;
    }

    listen(listener, 10);
    while (1) {
        sleep(1);
        sock = accept(listener, NULL, NULL);
        bytes_read = recv(sock, &message, sizeof(message), 0);
        switch(message.type) {
            case START:
                ret = read_data(current_iface);
                if (ret == -1) 
                    break;
                sniffer_state = START;
                break;
            case STOP:
                ret = save_data(current_iface);
                if (ret == -1) 
                    break;
                sniffer_state = STOP;
                break;
            case SELECT:
                if (strlen(current_iface))
                    save_data(current_iface);
                strcpy(current_iface, message.str);
                if (getifconf(current_iface, &ifp, PROMISC_MODE_ON) < 0) {
                    printf("%s:No such iface\n",__func__);
                    break;
                }

                if ((eth0_if = getsock_recv(ifp.index)) < 0) {
                    perror("getsock_recv");
                    break;
                }
                break;
            case SHOW_COUNT:
                show_count(message.str);
                break;
            case STAT:
                show_stat(message.str);
                break;
         break;
        }
    } 

    return NULL;
}

static int daemon_handler(void) {
    int thread_id1, result;
    pthread_t thread1;
    thread_id1 = 1;
    int raw_socket;
    int data_size;
    int count = 0;
    int i;
    __u32 num = 0;
    int rec = 0, ihl = 0;
    struct iphdr ip; // структура для хранения IP заголовка пакета
    static struct sigaction act;

    thread_id1 = pthread_create(&thread1, NULL, listen_thread, NULL);
    if (thread_id1 != 0) {
        printf("can't create thread");
        return -1;
    }
    if (getifconf("enp0s3", &ifp, PROMISC_MODE_ON) < 0) {
        perror("getifconf");
        return -1;
    }

    if ((eth0_if = getsock_recv(ifp.index)) < 0) {
        perror("getsock_recv");
        return -1;
    }

    for (;;) {
        if (sniffer_state == START) {
            memset(buff, 0, BUF_SIZE);
            rec = recvfrom(eth0_if, (char *)buff, ifp.mtu + 18, 0, NULL, NULL);
            if (rec < 0) {
                perror("recvfrom");
                printf("res = %d\n",rec);
                return -1;
            }
            memcpy((void *)&ip, buff + ETH_HLEN, sizeof(struct iphdr));
            if ((ip.version) != 4)
                continue;

            struct in_addr dest;
            dest.s_addr = ip.daddr;
            update_counter(dest.s_addr, 1);
            //printf("%s count = %d, \n",inet_ntoa(dest), get_key(root_rbtree, dest.s_addr));
        }
    }

    return 0;
}

int main(int argc, char* argv[]) {
    pid_t parpid;

    parpid = fork();
    if (parpid < 0) {
        printf("f\ncan't fork\n");
        return parpid;
    } else if (parpid == 0) {
        setsid();
        daemon_handler();
        return 0;
    }
}
