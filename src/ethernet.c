#include "ethernet.h"
#include "network_layout.h"

void analyze_ethernet_hearder(const u_char *packet, uint len)
{
	print_packet(len, (uint16_t *)packet);
	struct ether_header *eth_header = (struct ether_header *)packet;

	printf("destination host : %s\n",
		ether_ntoa((const struct ether_addr *)eth_header->ether_dhost));
	printf("source host: %s\n",
		ether_ntoa((const struct ether_addr *)eth_header->ether_shost));

	printf("Protocole: ");
	switch(ntohs(eth_header->ether_type))
	{
		case ETHERTYPE_IPV6:
			puts("IPV6");
			ipv6_header_analyze(packet + sizeof(struct ether_header),
				len - sizeof(struct ether_header));
			break;
		case ETHERTYPE_IP:
			puts("IPV4");
			ipv4_header_analyze(packet + sizeof(struct ether_header),
				len - sizeof(struct ether_header));
			break;
		case ETHERTYPE_ARP:
			puts("ARP");
			arp_header_analyze(packet + sizeof(struct ether_header));
			break;
		case ETHERTYPE_REVARP:
			puts("RARP");
			rarp_header_analyze(packet + sizeof(struct ether_header));
			break;
		default:
			puts("Unknown type...");
	}
}