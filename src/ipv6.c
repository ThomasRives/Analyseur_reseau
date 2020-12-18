#include "ipv6.h"

void 
ipv6_header_analyze(const u_char *packet, uint length, int verbose)
{
	struct ip6_hdr *ipv6_header = (struct ip6_hdr *)packet;
	struct ipv6_f32_parse f32_bits = parse_f32_ipv6(
		ntohl(ipv6_header->ip6_flow));

	char buf_adr1[INET6_ADDRSTRLEN];
	char buf_adr2[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ipv6_header->ip6_src, buf_adr1, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &ipv6_header->ip6_dst, buf_adr2, INET6_ADDRSTRLEN);
	if(verbose == 1)
	{
		printf("Src: %s ", buf_adr1);
		printf("Dst: %s ", buf_adr2);
	}
	else if(verbose == 2)
	{
		printf("Source address: %s\t", buf_adr1);
		printf("Destination address: %s\n", buf_adr2);
	}
	else
	{
		printf("Version: %i\n", f32_bits.version);
		printf("Trafic class: %x\n", f32_bits.tc);
		printf("ID: 0x%x\n", f32_bits.id);
		printf("Length: %i\n", ntohs(ipv6_header->ip6_plen));
		printf("Hop limit: %i\n", ipv6_header->ip6_hlim);

		printf("Source address: %s\n", buf_adr1);
		printf("Destination address: %s\n", buf_adr2);
	}

	ipv6_analyze_next_header(packet + sizeof(struct ip6_hdr),
							 length - sizeof(struct ip6_hdr),
							 ipv6_header->ip6_nxt,
							 verbose);
}

void
ipv6_analyze_next_header(const u_char *packet, uint len, uint8_t nxt_head,
	int verbose)
{
	if(verbose == 3)
		printf("Next header: ");
	switch (nxt_head)
	{
		case IPV6_HOP_BY_HOP:
			puts("Hop-by-hop Options Header (0)");
			break;
		case IPV6_TCP:
			print_bg_green("TCP", 0);
			if(verbose < 3)
				printf(" ");
			else
				puts(" (6)");
			tcp_header_analyze(packet, len, verbose);
			break;
		case IPV6_UDP:
			print_bg_yellow("UDP", 0);
			if (verbose < 3)
				printf(" ");
			else
				print_bg_yellow(" (17)", 1);
			udp_header_analyze(packet, len, verbose);
			break;
		case IPV6_ENCAPS_V6_HEADER:
			puts("Encapsulated IPv6 Header (41)");
			break;
		case IPV6_ROUTING_HEADER:
			puts("Routing Header (43)");
			break;
		case IPV6_FRAG_HEADER:
			puts("Fragment Header (44)");
			break;
		case IPV6_RES_RSV:
			puts("Resource ReSerVation Protocol (46)");
			break;
		case IPV6_SEC_PAYL:
			puts("Encapsulating Security Payload (50)");
			break;
		case IPV6_AUTH_HEADER:
			puts("Authentication Header (51)");
			break;
		case IPV6_ICMPV6:
			print_bg_red("ICMPv6", 0);
			if(verbose == 1)
			{
				puts("");
				return;
			}
			else if (verbose == 2)
				printf(" ");
			else
				print_bg_red(" (58)", 1);
			icmpv6_header_analyze(packet, verbose);
			break;
		case IPV6_NO:
			puts("No next header (59)");
			break;
		case IPV6_DEST_OPT_HEADER:
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