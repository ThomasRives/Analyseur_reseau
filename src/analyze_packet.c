#include "analyze_packet.h"
#include "network_layout.h"
#include "args.h"

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	Options options = *(Options *)args;
	(void)options;
	print_packet(header->len, (uint16_t *)packet);
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
				header->len - sizeof(struct ether_header));
			break;
		case ETHERTYPE_IP:
			puts("IPV4");
			ipv4_header_analyze(packet + sizeof(struct ether_header),
				header->len - sizeof(struct ether_header));
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

void
print_packet(uint pack_length, const uint16_t *packet)
{
	static int nb_pack = 0;
	nb_pack++;
	uint i = 0;

	printf("___Packet number %i___\n", nb_pack);
	printf("Packet's length: %i\n\n", pack_length);
	
	while(i < pack_length)
	{
		if(i%8 == 0)
			puts("");
			
		if(i%2 == 0)
			printf("%.2x", ntohs(*(packet + i/2)) >> 8);
		else
			printf("%.2x ", ntohs(*(packet + (i - 1)/2)) & 0x00ff);

		i++;
	}

	printf("\n\n");
	fflush(stdout);
}
