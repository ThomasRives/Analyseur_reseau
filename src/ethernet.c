#include "ethernet.h"
#include "network_layout.h"

void analyze_ethernet_hearder(const u_char *packet, uint len)
{
	print_packet(len, packet);
	struct ether_header *eth_header = (struct ether_header *)packet;

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
	printf("Protocole: ");
	switch(prot)
	{
		case ETHERTYPE_IPV6:
			puts("IPV6");
			ipv6_header_analyze(packet, len);
			break;
		case ETHERTYPE_IP:
			puts("IPV4");
			ipv4_header_analyze(packet, len);
			break;
		case ETHERTYPE_ARP:
			puts("ARP");
			arp_header_analyze(packet);
			break;
		case ETHERTYPE_REVARP:
			puts("RARP");
			rarp_header_analyze(packet);
			break;
		default:
			puts("Unknown type...");
	}
}
