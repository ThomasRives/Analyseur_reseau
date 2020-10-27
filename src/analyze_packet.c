#include "analyze_packet.h"
#include "ip_analyzer.h"

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	(void)args;
	print_packet(header->len, (uint16_t *)packet);
	struct ether_header *eth_header = (struct ether_header *)packet;

	printf("destination host : %s\n",
		ether_ntoa((const struct ether_addr *)eth_header->ether_dhost));
	printf("source host: %s\n",
		ether_ntoa((const struct ether_addr *)eth_header->ether_shost));

	switch(ntohs(eth_header->ether_type))
	{
		case ETHERTYPE_IPV6:
			printf("protocole IPV6\n");
			break;
		case ETHERTYPE_IP:
			printf("protocole IPV4\n");
			ipv4_header_analyze(packet + sizeof(struct ether_header));
			break;
		case ETHERTYPE_ARP:
			printf("protocol ARP\n");
			break;
		case ETHERTYPE_REVARP:
			printf("protocol RARP\n");
			break;
		default:
			printf("Unknown type...\n");
	}
}

void
print_packet(uint pack_length, uint16_t *packet)
{
	static int nb_pack = 0;
	nb_pack++;

	printf("___Packet number %i___\n", nb_pack);
	printf("Packet's length: %i\n\n", pack_length);

	for(uint i = 0; i < pack_length; i+=2, packet++)
	{
    	if(i%8 == 0)
    		printf("\n");
    	printf("%.4x ", *packet);
 	}

	printf("\n\n");
	fflush(stdout);
}
