void tv_sub(struct timeval *out, struct timeval *in);
void print_statistics(double rtt, int packet_loss,int ttl,int focus,int count);
unsigned short cal_chksum(unsigned short *addr, int len);
