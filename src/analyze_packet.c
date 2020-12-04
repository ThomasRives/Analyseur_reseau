#include "analyze_packet.h"
#include "ethernet.h"
#include "args.h"

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	Options options = *(Options *)args;
	(void)options;
	(void)header;
	analyze_ethernet_hearder(packet, header->len);
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
