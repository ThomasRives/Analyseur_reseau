#include "ip_analyzer.h"


void
ipv4_header_analyze(const u_char *packet)
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

	printf("Protocol used: ");
	switch (ip_header->protocol) {
		case IPPROTO_TCP:
			printf("TCP\n");
			break;
		case IPPROTO_UDP:
			printf("UDP\n");
			break;
		case IPPROTO_ICMP:
			printf("ICMP\n");
			break;
		case IPPROTO_IPV6:
			printf("IPv6\n");
			break;
	}
}

void 
ipv6_header_analyze(const u_char *packet)
{
	struct ip6_hdr *ipv6_header = (struct ip6_hdr *)packet;
	struct ipv6_f32_parse f32_bits = parse_f32_ipv6(ntohl(ipv6_header->ip6_flow));
	printf("Version: %i\n", f32_bits.version);
	printf("Trafic class: %x\n", f32_bits.tc);
	printf("ID: 0x%x\n", f32_bits.id);
	printf("Length: %i\n", ntohs(ipv6_header->ip6_plen));

	printf("Next header: ");
	switch (ipv6_header->ip6_nxt)
	{
		case 0:
			printf("Hop-by-hop Options Header");
			break;
		case 6:
			printf("TCP");
			break;
		case 17:
			printf("UDP");
			break;
		case 41:
			printf("Encapsulated IPv6 Header");
			break;
		case 43:
			printf("Routing Header");
			break;
		case 44:
			printf("Fragment Header");
			break;
		case 46:
			printf("Resource ReSerVation Protocol");
			break;
		case 50:
			printf("Encapsulating Security Payload");
			break;
		case 51:
			printf("Authentication Header");
			break;
		case 58:
			printf("ICMPv6");
			break;
		case 59:
			printf("No next header");
			break;
		case 60:
			printf("Destination Options Header");
			break;
		default:
			printf("Unsuported next header");
	}
	printf(" (%i)\n", ipv6_header->ip6_nxt);
	printf("Hop limit: %i\n", ipv6_header->ip6_hlim);
	char buf_adr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ipv6_header->ip6_src, buf_adr, INET6_ADDRSTRLEN);
	printf("Source address: %s\n", buf_adr);
	inet_ntop(AF_INET6, &ipv6_header->ip6_dst, buf_adr, INET6_ADDRSTRLEN);
	printf("Destination address: %s\n", buf_adr);
}

struct ipv6_f32_parse
parse_f32_ipv6(uint32_t first32_bits)
{
	struct ipv6_f32_parse parsed;
	uint32_t vers_mask = 0xf0000000;
	uint32_t traf_class_mask = 0x0ff00000;
	uint32_t id_mask = 0x000fffff;
	parsed.version = (first32_bits & vers_mask) >> 28;
	parsed.tc = (first32_bits & traf_class_mask) >> 20;
	parsed.id = (first32_bits & id_mask);
	return parsed;
}