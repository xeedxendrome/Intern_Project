#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void filtercompilerandsetter(pcap_t *handle, char *filter_exp, bpf_u_int32 net)
{
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        exit(1);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        exit(1);
    }
    return;
}

pcap_t *session_create(char *devname, char *filter_exp)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 mask;
    bpf_u_int32 net;
    // net is required for filtercompilerandsetter

    if (pcap_lookupnet(devname, &net, &mask, errbuf) == -1)
    {
        net = 0;
        mask = 0;
    }
    // starting the session
    handle = pcap_open_live(devname, 65536, 1, 1000, errbuf);

    filtercompilerandsetter(handle, filter_exp, net);
    return handle;
}
