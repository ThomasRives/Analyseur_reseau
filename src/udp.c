#include "udp.h"

void 
udp_header_analyze(const u_char *packet, uint length)
{
	struct udphdr *udp_header = (struct udphdr *)packet;
	printf("Source port: %u\n", ntohs(udp_header->uh_sport));
	printf("Destination port: %u\n", ntohs(udp_header->uh_dport));
	printf("Length: %u\n", ntohs(udp_header->uh_ulen));
	printf("Checksum: 0x%x\n", ntohs(udp_header->uh_sum));
	demult_port(ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport),
		packet + sizeof(struct udphdr), length - sizeof(struct udphdr));
}