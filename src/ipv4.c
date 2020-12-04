#include "ipv4.h"

void
ipv4_header_analyze(const u_char *packet, uint length)
{
	struct iphdr *ip_header = (struct iphdr *)packet;
	printf("IHL: %u bytes\n", ip_header->ihl*4);
	printf("Type of service: %u TODO\n", ip_header->tos);//TODO
	printf("Total length: %u\n", ip_header->tot_len);
	printf("Packet's ID: %u\n", ip_header->id);
	printf("Packet's flags: %u\n", ip_header->frag_off >> 13);
	printf("Fragment offset: %u\n", ip_header->frag_off & 0x3f);
	printf("Time to live: %u\n", ip_header->ttl);
	printf("Checksum : %u\n", ip_header->check);
	printf("Source address : %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
	printf("Destination address: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));
	//TODO Read options ?

	printf("Protocol used: (%i) ", ip_header->protocol);
	switch (ip_header->protocol) 
	{
		case IPPROTO_TCP:
			puts("TCP");
			tcp_header_analyze(packet + ip_header->ihl * 4,
				length - ip_header->ihl * 4);
			break;
		case IPPROTO_UDP:
			puts("UDP");
			udp_header_analyze(packet + ip_header->ihl * 4,
				length - ip_header->ihl * 4);
			break;
		case IPPROTO_ICMP:
			puts("ICMP");
			icmp_header_analyze(packet + ip_header->ihl * 4);
			break;
		case IPPROTO_IPV6:
			puts("IPv6");
			break;
		default:
			puts("Not supported");
	}
}