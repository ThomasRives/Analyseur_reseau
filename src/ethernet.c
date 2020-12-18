#include "ethernet.h"
#include "network_layout.h"

void analyze_ethernet_hearder(const u_char *packet, uint len)
{
	puts("\n");
	print_packet(len, packet);
	struct ether_header *eth_header = (struct ether_header *)packet;
	printf("Protocol: ");
	print_bg_red("Ethernet", 1);
	printf("destination host : %s\n",
		ether_ntoa((const struct ether_addr *)eth_header->ether_dhost));
	printf("source host: %s\n",
		ether_ntoa((const struct ether_addr *)eth_header->ether_shost));

	ethernet_demult_prot(packet + sizeof(struct ether_header),
						 len - sizeof(struct ether_header),
						 ntohs(eth_header->ether_type));
}

void
ethernet_demult_prot(const u_char *packet, uint len, uint16_t prot)
{
	printf("\nProtocole: ");
	switch(prot)
	{
		case ETHERTYPE_IPV6:
			print_bg_blue("IPV6", 1);
			ipv6_header_analyze(packet, len);
			break;
		case ETHERTYPE_IP:
			print_bg_green("IPV4", 1);
			ipv4_header_analyze(packet, len);
			break;
		case ETHERTYPE_ARP:
			print_bg_cyan("ARP", 1);
			arp_header_analyze(packet);
			break;
		case ETHERTYPE_REVARP:
			print_bg_white("RARP", 1);
			rarp_header_analyze(packet);
			break;
		default:
			puts("Unknown type...");
	}
}
