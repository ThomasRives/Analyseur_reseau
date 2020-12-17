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
print_packet(uint pack_length, const u_char *packet)
{
	static int nb_pack = 0;
	nb_pack++;

	printf("___Packet number %i___\n", nb_pack);
	printf("Packet's length: %i\n\n", pack_length);
	
	for(uint i = 0; i < pack_length; i++)
	{
		if(i%8 == 0)
			printf("\n");
		else if(i%4 == 0)
			printf(" ");

		printf("%.2x ", *(packet + i));
	}

	printf("\n\n");
	fflush(stdout);
}
