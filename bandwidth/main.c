#include <pcap.h>
#include <string.h> //for string related functions
#include <stdio.h>
#include <signal.h> // Include the header file for sigaction
#include <unistd.h> // Include the header file for alarm
#include "session_creation.h"

int total = 0, tcp = 0, udp = 0, icmp = 0, igmp = 0, others = 0;
long total_bytes = 0, tcp_bytes = 0, udp_bytes = 0, icmp_bytes = 0, other_bytes = 0;
long total_bytes_banwidth = 0, tcp_bytes_banwidth = 0, udp_bytes_banwidth = 0, icmp_bytes_banwidth = 0, other_bytes_banwidth = 0;

void bandwidth_calculator()
{
    total_bytes_banwidth = total_bytes * 8;
    tcp_bytes_banwidth = tcp_bytes * 8;
    udp_bytes_banwidth = udp_bytes * 8;
    icmp_bytes_banwidth = icmp_bytes * 8;
    other_bytes_banwidth = other_bytes * 8;
    printf("Bandwidth in bits/sec, TCP_banwidth: %ld  , UDP_banwidth: %ld , ICMP_banwidth: %ld , Others_banwidth: %ld ,  Total_banwidth: %ld\n", tcp_bytes_banwidth, udp_bytes_banwidth, icmp_bytes_banwidth, other_bytes_banwidth, total_bytes_banwidth);
    printf("Total packets: %d, TCP packets: %d, UDP packets: %d, ICMP packets: %d, Others packets: %d\n", total, tcp, udp, icmp, others);
    total = 0, tcp = 0, udp = 0, icmp = 0, others = 0;
    total_bytes = 0, tcp_bytes = 0, udp_bytes = 0, icmp_bytes = 0, other_bytes = 0;
}

void on_alarm(int signum)
{

    bandwidth_calculator();

    alarm(1);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    static int count = 1;

    long *rex = (long *)args;

    int size_packet = header->caplen;
    total_bytes += size_packet;

    count++;

    struct sniff_ip *iph = (struct sniff_ip *)(buffer + sizeof(struct sniff_ethernet));
    ++total;
    switch (iph->ip_shubhanshu)
    {
    case 1: // ICMP Protocol
        ++icmp;
        icmp_bytes += size_packet;
        break;

    case 6: // TCP Protocol
        ++tcp;
        tcp_bytes += size_packet;
        break;

    case 17: // UDP Protocol
        ++udp;
        udp_bytes += size_packet;
        break;

    default: // Some Other Protocol like ARP etc.
        other_bytes += size_packet;
        ++others;
        break;
    }
}

int main(int argc, char *argv[])
{
    act.sa_handler = &on_alarm;
    act.sa_mask = 0;
    act.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &act, NULL);
    alarm(1);
    char *devname;
    pcap_t *handle;

    char filter_exp[10000];
    strcpy(filter_exp, argv[1]);

    devname = argv[2];
    long total_bytes = 0;
    total_bytes = 0;
    handle = session_create(devname, filter_exp);

    pcap_loop(handle, 10000, process_packet, (u_char *)&total_bytes);

    pcap_close(handle);
    return (0);
}
