#include "ipv4.h"

void
ipv4_header_analyze(const u_char *packet, uint length)
{
	struct iphdr *ip_header = (struct iphdr *)packet;
	printf("IHL: %u bytes\n", ip_header->ihl*4);
	printf("Type of service: %u TODO\n", ip_header->tos);//TODO
	printf("Total length: %u\n", ntohs(ip_header->tot_len));
	printf("Packet's ID: 0x%x\n", ntohs(ip_header->id));
	ipv4_print_flags(ip_header->frag_off & IPV4_FLAGS);
	printf("Fragment offset: %u\n", ip_header->frag_off & IPV4_FRAG_OFF);
	printf("Time to live: %u\n", ip_header->ttl);
	printf("Checksum : 0x%x\n", ntohs(ip_header->check));
	printf("Source address : %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
	printf("Destination address: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));
	//TODO Read options ?

	ipv4_demult_prot(packet + ip_header->ihl * 4,
					 length - ip_header->ihl * 4,
					 ip_header->protocol);
}

void
ipv4_print_flags(uint8_t flags)
{
	puts("Flags:");
	if (flags & IPV4_FLAG_DO_NOT_FRAG)
		puts("\tDo not fragment");
	if (flags & IPV4_FLAG_MORE_FRAG)
		puts("\tMore fragment");
}

void
ipv4_demult_prot(const u_char *packet, uint len, uint8_t prot)
{
	printf("Protocol used:");
	switch (prot) 
	{
		case IPPROTO_TCP:
			printf("TCP (%i)\n", prot);
			tcp_header_analyze(packet, len);
			break;
		case IPPROTO_UDP:
			printf("UDP (%i)\n", prot);
			udp_header_analyze(packet, len);
			break;
		case IPPROTO_ICMP:
			printf("ICMP (%i)\n", prot);
			icmp_header_analyze(packet);
			break;
		case IPPROTO_IPV6:
			printf("IPv6 (%i)\n", prot);
			break;
		case IPPROTO_SCTP:
			printf("SCTP (%i)\n", prot);
			sctp_analayze(packet, len);
			break;
		default:
			puts("Not supported");
	}
}