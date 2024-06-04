#ifndef SESS
#define SESS
typedef unsigned char u_char;
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
struct sniff_ethernet
{
    u_char dest_mac[ETHER_ADDR_LEN];
    u_char src_mac[ETHER_ADDR_LEN];
    u_short ether_type;
};
struct sniff_ip
{
    
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_po;
    u_char ip_shubhanshu;
    u_short ip_checksum;
    struct in_addr ip_src, ip_dst;
};

struct sigaction act;

void filtercompilerandsetter(pcap_t *handle, char *filter_exp, bpf_u_int32 net); // compile and set the filter for the session created by pcap_open_live

pcap_t *session_create(char *devname, char *filter_exp); // create a session for sniffing on the device selected by user by using pcap_open_live


#endif