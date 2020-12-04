#include "arp.h"

void
arp_header_analyze(const u_char *packet)
{
	struct ether_arp *arp_hdr = (struct ether_arp *)packet;
	printf("Hardware type: ");
	switch (ntohs(arp_hdr->ea_hdr.ar_hrd))
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
	switch(ntohs(arp_hdr->ea_hdr.ar_pro))
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

	printf("Hardware Address Length: %i\n", arp_hdr->ea_hdr.ar_hln);
	printf("Protocol Address Length: %i\n", arp_hdr->ea_hdr.ar_pln);
	printf("Operation: ");
	switch (ntohs(arp_hdr->ea_hdr.ar_op))
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
	print_arp_hard_addr(arp_hdr->ea_hdr.ar_hln * 8, arp_hdr->arp_sha, 1);
	print_arp_pro_addr(arp_hdr->ea_hdr.ar_pln * 8, arp_hdr->arp_spa, 1);
	print_arp_hard_addr(arp_hdr->ea_hdr.ar_hln * 8, arp_hdr->arp_tha, 0);
	print_arp_pro_addr(arp_hdr->ea_hdr.ar_pln * 8, arp_hdr->arp_tpa, 0);
}

void 
print_arp_hard_addr(unsigned int hlen, uint8_t *beg_addr, short sender)
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
print_arp_pro_addr(unsigned int hlen, uint8_t *beg_addr, short sender)
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