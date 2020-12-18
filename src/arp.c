#include "arp.h"

void
arp_header_analyze(const u_char *packet, int verbose)
{
	struct ether_arp *arp_hdr = (struct ether_arp *)packet;

	if(verbose == 2)
	{
		arp_print_hard_addr(arp_hdr->ea_hdr.ar_hln * 8, arp_hdr->arp_sha, 1);
		printf("\t");
		arp_print_hard_addr(arp_hdr->ea_hdr.ar_hln * 8, arp_hdr->arp_tha, 0);
		puts("");
	}
	else
	{
		arp_print_hard_type(ntohs(arp_hdr->ea_hdr.ar_hrd));

		arp_print_prot_type(ntohs(arp_hdr->ea_hdr.ar_pro));

		printf("Hardware Address Length: %i\n", arp_hdr->ea_hdr.ar_hln);
		printf("Protocol Address Length: %i\n", arp_hdr->ea_hdr.ar_pln);

		arp_print_op(ntohs(arp_hdr->ea_hdr.ar_op));

		arp_print_hard_addr(arp_hdr->ea_hdr.ar_hln * 8, arp_hdr->arp_sha, 1);
		puts("");
		arp_print_pro_addr(arp_hdr->ea_hdr.ar_pln * 8, arp_hdr->arp_spa, 1);
		arp_print_hard_addr(arp_hdr->ea_hdr.ar_hln * 8, arp_hdr->arp_tha, 0);
		puts("");
		arp_print_pro_addr(arp_hdr->ea_hdr.ar_pln * 8, arp_hdr->arp_tpa, 0);
	}
}

void
arp_print_hard_type(unsigned int hard_type)
{
	printf("Hardware type: ");
	switch (hard_type)
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
}

void
arp_print_prot_type(uint prot_type)
{
	printf("Protocol type: ");
	switch (prot_type)
	{
		case ETHERTYPE_IPV6:
			print_bg_blue("IPV6", 1);
			break;
		case ETHERTYPE_IP:
			print_bg_green("IPV4", 1);
			break;
		case ETHERTYPE_ARP:
			print_bg_cyan("ARP", 1);
			break;
		case ETHERTYPE_REVARP:
			print_bg_cyan("RARP", 1);
			break;
		default:
			puts("Unknown type...");
	}
}

void
arp_print_op(uint op)
{
	printf("Operation: ");
	switch (op)
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
}

void 
arp_print_hard_addr(unsigned int hlen, uint8_t *beg_addr, short sender)
{
	if(sender)
		printf("Sender hardware address: ");
	else
		printf("Target hardware address: ");

	if(hlen != (ETH_ALEN * 8))
		printf("Unknown type of address");
	else
		printf("%s", ether_ntoa((const struct ether_addr *)beg_addr));
}


void
arp_print_pro_addr(unsigned int hlen, uint8_t *beg_addr, short sender)
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