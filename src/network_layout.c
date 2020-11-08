#include "network_layout.h"


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
			icmpv6_header_analyze(packet + sizeof(struct ip6_hdr));
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
	uint32_t vers_mask = 0xf0000000;
	uint32_t traf_class_mask = 0x0ff00000;
	uint32_t id_mask = 0x000fffff;
	parsed.version = (first32_bits & vers_mask) >> 28;
	parsed.tc = (first32_bits & traf_class_mask) >> 20;
	parsed.id = (first32_bits & id_mask);
	return parsed;
}

void
arp_header_analyze(const u_char *packet)
{
	struct arphdr *arp_hdr = (struct arphdr *)packet;
	printf("Hardware type: ");
	switch (ntohs(arp_hdr->ar_hrd))
	{
		case ARPHRD_ETHER:
			puts("Ethernet (1)");
			break;
		case ARPHRD_EETHER:
			puts("Experimental Ethernet (2)");
			break;
		case ARPHRD_PRONET:
			puts("PROnet token ring (4)");
			break;
		default:
			puts("Not supported...");
	}
	printf("Protocol type: ");
	switch(ntohs(arp_hdr->ar_pro))
	{
		case ETHERTYPE_IPV6:
			puts("IPV6");
			break;
		case ETHERTYPE_IP:
			puts("IPV4");
			break;
		case ETHERTYPE_ARP:
			puts("ARP");
			break;
		case ETHERTYPE_REVARP:
			puts("RARP");
			break;
		default:
			puts("Unknown type...");
	}

	printf("Hardware Address Length: %i\n", arp_hdr->ar_hln * 8);
	printf("Protocol Address Length: %i\n", arp_hdr->ar_pln * 8);
	printf("Operation: ");
	switch (ntohs(arp_hdr->ar_op))
	{
		case ARPOP_REQUEST:
			puts("ARP Request (1)");
			break;
		case ARPOP_REPLY:
			puts("ARP Reply (2)");
			break;
		case ARPOP_RREQUEST:
			puts("RARP Request (3)");
			break;
		case ARPOP_RREPLY:
			puts("RARP Reply (4)");
			break;
		case ARPOP_InREQUEST:
			puts("InRARP Request (8)");
			break;
		case ARPOP_InREPLY:
			puts("InRARP Reply (9)");
			break;
		case ARPOP_NAK:
			puts("ARP NAK (10)");
			break;
		default:
			puts("Unknown...");
	}
	print_arp_hard_addr(arp_hdr->ar_hln * 8, (uint32_t *)(packet + 8) , 1);
	print_arp_pro_addr(arp_hdr->ar_pln * 8, (uint32_t *)(packet + 8 + arp_hdr->ar_hln), 1);
	print_arp_hard_addr(arp_hdr->ar_hln * 8, (uint32_t *)(packet + 8 + arp_hdr->ar_hln + arp_hdr->ar_pln), 0);
	print_arp_pro_addr(arp_hdr->ar_pln * 8, (uint32_t *)(packet + 8 + 2 * arp_hdr->ar_hln + arp_hdr->ar_pln), 0);
	// struct ether_arp
	// {
	// 	struct arphdr ea_hdr;			/* fixed-size header */
	// 	u_char arp_sha[ETHER_ADDR_LEN]; /* sender hardware address */
	// 	u_char arp_spa[4];				/* sender protocol address */
	// 	u_char arp_tha[ETHER_ADDR_LEN]; /* target hardware address */
	// 	u_char arp_tpa[4];				/* target protocol address */
	// };
}

void 
rarp_header_analyze(const u_char *packet)
{
	arp_header_analyze(packet);
}

void 
print_arp_hard_addr(unsigned int hlen, uint32_t *beg_addr, short sender)
{
	if(sender)
		printf("Sender hardware address: ");
	else
		printf("Target hardware address: ");

	if(hlen != (ETH_ALEN * 8))
		puts("Unknown type of address");
	else
		printf("%s\n", ether_ntoa((const struct ether_addr *)beg_addr));
}


void
print_arp_pro_addr(unsigned int hlen, uint32_t *beg_addr, short sender)
{
	if(sender)
		printf("Sender protocol address: ");
	else
		printf("Target protocol address: ");

	if (hlen == 32)
		printf("%s\n", inet_ntoa(*(struct in_addr *)beg_addr));
	else
	{
		char buf_adr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, beg_addr, buf_adr, INET6_ADDRSTRLEN);
		printf("%s\n", buf_adr);
	}
}