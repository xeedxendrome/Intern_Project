#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h> // addr
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>


struct MinMaxAvg
{

    double min;
    double max;
    double rtt_col[10000];
    double avg;
    int total_packets;
    int packets_received;
};
int occupied = 0;

struct MinMaxAvg array[10000];
void tv_sub(struct timeval *out, struct timeval *in)
{

    if ((out->tv_usec -= in->tv_usec) < 0)
    {
        --out->tv_sec;
        out->tv_usec += 1000000;
    }

    out->tv_sec -= in->tv_sec;
}

void print_statistics(double rtt, int packet_loss, int ttl, int focus, int count)

{
    double loss = 0.0;

    int index = 0;

    int flag = -1;
    if (occupied >= ttl)
    {
        flag = ttl - 1;
    }

    if (flag == -1)
    {

        array[occupied].min = rtt;
        array[occupied].max = rtt;
        array[occupied].avg = rtt;
        array[occupied].rtt_col[0] = rtt;
        array[occupied].total_packets = 1;
        if (packet_loss)
        {

            loss = (double)(array[ttl - 1].total_packets - array[ttl - 1].packets_received) / (double)array[ttl - 1].total_packets;
            loss *= 100;
            printf("Loss: %.2f%%\n", loss);
            occupied++;
            return;
        }
        else
        {
            array[occupied].packets_received = 1;
            loss = (double)(array[occupied].total_packets - array[occupied].packets_received) / (double)array[occupied].total_packets;
            loss *= 100;
            printf("Loss: %.2f%%\n", loss);
            printf("Min: %.3f ms, Max: %.3f ms, Avg: %.3f ms\n", array[occupied].min, array[occupied].max, array[occupied].avg);
            occupied++;
        }
    }
    else
    {
        if (packet_loss)
        {

            array[ttl - 1].total_packets++;
            loss = (double)(array[ttl - 1].total_packets - array[ttl - 1].packets_received) / (double)array[ttl - 1].total_packets;
            loss *= 100;
            printf("Loss: %.2f%%\n", loss);
            return;
        }
        if (rtt < array[flag].min)
        {
            array[flag].min = rtt;
        }
        if (rtt > array[flag].max)
        {
            array[flag].max = rtt;
        }
        if (count >= focus)
        {
            for (int index = 1; index < occupied; index++)
            {
                array[flag].rtt_col[index - 1] = array[flag].rtt_col[index];
            }
            array[flag].rtt_col[focus - 1] = rtt;
            array[flag].avg = 0.0;
            for (int index = 0; index < focus; index++)
            {
                array[flag].avg += array[flag].rtt_col[index];
            }
            array[flag].avg /= (double)focus;
        }
        else
        {
            array[flag].rtt_col[count - 1] = rtt;
            array[flag].avg = 0.0;
            for (index = 0; index < count; index++)
            {
                array[flag].avg += array[flag].rtt_col[index];
            }
            array[flag].avg /= (double)count;
        }
        array[flag].packets_received++;
        array[flag].total_packets++;

        loss = (double)(array[flag].total_packets - array[flag].packets_received) / (double)array[flag].total_packets;
        loss *= 100;
        printf("Loss: %.2f%%\n", loss);
        printf("Min: %.3f ms, Max: %.3f ms, Avg: %.3f ms\n", array[flag].min, array[flag].max, array[flag].avg);
    }
}

unsigned short cal_chksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;

    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w;

        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}
