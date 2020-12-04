#include "ipv6.h"

void 
ipv6_header_analyze(const u_char *packet, uint length)
{
	struct ip6_hdr *ipv6_header = (struct ip6_hdr *)packet;
	struct ipv6_f32_parse f32_bits = parse_f32_ipv6(ntohl(ipv6_header->ip6_flow));
	printf("Version: %i\n", f32_bits.version);
	printf("Trafic class: %x\n", f32_bits.tc);
	printf("ID: 0x%x\n", f32_bits.id);
	printf("Length: %i\n", ntohs(ipv6_header->ip6_plen));

	printf("Hop limit: %i\n", ipv6_header->ip6_hlim);
	char buf_adr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ipv6_header->ip6_src, buf_adr, INET6_ADDRSTRLEN);
	printf("Source address: %s\n", buf_adr);
	inet_ntop(AF_INET6, &ipv6_header->ip6_dst, buf_adr, INET6_ADDRSTRLEN);
	printf("Destination address: %s\n", buf_adr);

	printf("Next header: ");
	switch (ipv6_header->ip6_nxt)
	{
		case 0:
			puts("Hop-by-hop Options Header (0)");
			break;
		case 6:
			puts("TCP (6)");
			tcp_header_analyze(packet + sizeof(struct ip6_hdr),
				length - sizeof(struct ip6_hdr));
			break;
		case 17:
			puts("UDP (17)");
			udp_header_analyze(packet + sizeof(struct ip6_hdr),
				length - sizeof(struct ip6_hdr));
			break;
		case 41:
			puts("Encapsulated IPv6 Header (41)");
			break;
		case 43:
			puts("Routing Header (43)");
			break;
		case 44:
			puts("Fragment Header (44)");
			break;
		case 46:
			puts("Resource ReSerVation Protocol (46)");
			break;
		case 50:
			puts("Encapsulating Security Payload (50)");
			break;
		case 51:
			puts("Authentication Header (51)");
			break;
		case 58:
			puts("ICMPv6 (58)");
			icmpv6_header_analyze(packet + sizeof(struct ip6_hdr), 
				length - sizeof(struct ip6_hdr));
			break;
		case 59:
			puts("No next header (59)");
			break;
		case 60:
			puts("Destination Options Header (60)");
			break;
		default:
			puts("Unsuported next header");
	}
}

struct ipv6_f32_parse
parse_f32_ipv6(uint32_t first32_bits)
{
	struct ipv6_f32_parse parsed;
	parsed.version = (first32_bits & VERS_MASK) >> 28;
	parsed.tc = (first32_bits & TRAF_CLASS_MASK) >> 20;
	parsed.id = (first32_bits & ID_MASK);
	return parsed;
}