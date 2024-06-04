
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "./calc.h"

#define PACKET_SIZE 4096
#define MAX_WAIT_TIME 1

char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];

int sockfd, datalen = 56;
char *arg1;
char *arg2;
uint16_t pid;

struct sockaddr_in dest_addr;
struct sockaddr_in from;
struct timeval tvrecv;

int pack(int pack_no);
void send_packet(void);
void recv_packet(void);
int unpack(char *buf, int len);

int pack(int pack_no)
{
    int packsize;

    struct icmp *icmp;
    struct timeval *tval;

    icmp = (struct icmp *)sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;
    icmp->icmp_id = pid;

    packsize = 8 + datalen;

    tval = (struct timeval *)icmp->icmp_data;
    gettimeofday(tval, NULL);
    icmp->icmp_cksum = cal_chksum((unsigned short *)icmp, packsize);

    return packsize;
}

void send_packet()
{
    int packetsize;

    packetsize = pack(0);

    if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
    {
        perror("sendto error");

        return;
    }
}

void recv_packet()
{

    int n, fromlen;
    extern int errno;

    fromlen = sizeof(from);

    if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, &fromlen)) < 0)
    {
        

        perror("recvfrom error");

        return;
    }

    gettimeofday(&tvrecv, NULL);

    if (unpack(recvpacket, n) == -1)
        return;
}

int unpack(char *buf, int len)
{
    int iphdrlen;

    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;

    double rtt;

    ip = (struct ip *)buf;
    iphdrlen = ip->ip_hl << 2;
    icmp = (struct icmp *)(buf + iphdrlen);
    len -= iphdrlen;

    if (len < 8)
    {
        printf("ICMP packets\'s length is less than 8\n");

        return -1;
    }

    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))
    {
        tvsend = (struct timeval *)icmp->icmp_data;

        tv_sub(&tvrecv, tvsend);

        rtt = tvrecv.tv_sec * 1000 + (double)tvrecv.tv_usec / 1000.0;

        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n", len,

               inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
    }
    else
        return -1;

    return 1;
}

void repeat_call()
{
    struct hostent *host;
    struct protoent *protocol;
    unsigned long inaddr = 0l;
    int size = 50 * 1024;

    if ((protocol = getprotobyname("icmp")) == NULL)
    {
        perror("getprotobyname");

        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)
    {
        perror("socket error");

        exit(1);
    }

    setuid(getuid());

    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    if ((inaddr = inet_addr(arg1)) == INADDR_NONE)
    {
        if ((host = gethostbyname(arg1)) == NULL)
        {
            perror("gethostbyname error");

            exit(1);
        }

        memcpy((char *)&dest_addr.sin_addr, host->h_addr, host->h_length);
    }
    else
        dest_addr.sin_addr.s_addr = inet_addr(arg1);

    pid = getpid();

    printf("PING %s(%s): %d bytes data in ICMP packets.\n", arg1, inet_ntoa(dest_addr.sin_addr), datalen);

    send_packet();

    recv_packet();

    close(sockfd);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("usage:%s hostname/IP address\n", argv[0]);

        exit(1);
    }
    arg1 = argv[1];

    while (1)
    {
        repeat_call();
        sleep(atoi(argv[2]));
    }

    return 0;
}