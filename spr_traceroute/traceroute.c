
#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "./calc.h"

#define PACKET_SIZE 4096

char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];

int sockfd, datalen = 56;
int nsend = 0, nreceived = 0;
int focus = 0;
int count = 0;
char *arg1;
int flag = 0;
int ttl = 0;
uint16_t pid;

struct sockaddr_in dest_addr; // to store destination address
struct sockaddr_in from;      // to store source address
struct timeval tvrecv;
struct timeval tvsend;

unsigned short cal_chksum(unsigned short *addr, int len);
int pack(int pack_no);
void send_packet(void);
void recv_packet(void);
int unpack(char *buf, int len);
void set_ttl(int ttl);

void set_ttl(int ttl)
{

    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
    {
        perror("setsockopt");
        exit(1);
    }
}

int pack(int pack_no)
{
    int packsize;

    struct icmp *icmp;

    icmp = (struct icmp *)sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;
    icmp->icmp_id = pid;

    packsize = 8 + datalen;

    gettimeofday(&tvsend, NULL);

    // printf("Current time: %ld.%06ld\n", tval->tv_sec, tval->tv_usec);
    icmp->icmp_cksum = cal_chksum((unsigned short *)icmp, packsize);

    return packsize;
}

void send_packet()
{

    int packetsize;

    packetsize = pack(nsend);

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
        print_statistics(0, 1, ttl, focus, count);

        return;
    }

    gettimeofday(&tvrecv, NULL);

    if (unpack(recvpacket, n) == -1)
    {

        return;
    }
}

int unpack(char *buf, int len)
{
    int iphdrlen;

    struct ip *ip;
    struct icmp *icmp;

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
    if ((icmp->icmp_type == 11) && (icmp->icmp_code == 0))
    {

        tv_sub(&tvrecv, &tvsend);

        rtt = tvrecv.tv_sec * 1000 + (double)tvrecv.tv_usec / 1000.0;

        printf("%d byte from %s: rtt=%.3f ms\n", len,

               inet_ntoa(from.sin_addr), rtt);
    }
    else if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))
    {

        tv_sub(&tvrecv, &tvsend);

        rtt = tvrecv.tv_sec * 1000 + (double)tvrecv.tv_usec / 1000.0;

        printf("%d byte from %s: rtt=%.3f ms\n", len,

               inet_ntoa(from.sin_addr), rtt);
        flag = 1;
    }
    else
        return -1;
    print_statistics(rtt, 0, ttl, focus, count);

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

    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    bzero(&dest_addr, sizeof(dest_addr));
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt failed\n");
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt failed\n");
    }
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

    printf("PING %s(%s): %d bytes data in ICMP packets.\n", arg1, inet_ntoa(dest_addr.sin_addr), datalen);

    setuid(getuid());

    pid = getpid();
    ttl = 0;
    int MAX_TTL = 30;

    for (ttl = 1; ttl <= MAX_TTL; ttl++)
    {

        printf("ttl=%d\n", ttl);
        set_ttl(ttl);

        send_packet();

        recv_packet();
        if (flag)
        {
            flag = 0;
            break;
        }
    }

    close(sockfd);
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("usage:%s hostname/IP address\n", argv[0]);

        exit(1);
    }
    arg1 = argv[1];
    focus = atoi(argv[3]);

    while (1)
    {
        count++;
        repeat_call();
        sleep(atoi(argv[2]));
    }

    return 0;
}
