#include "sctp.h"

void
sctp_analayze(const u_char *packet, uint length)
{
	(void)length;
	struct sctp_hdr *header = (struct sctp_hdr *)packet;
	printf("Source port: %u\n", ntohs(header->src_prt));
	printf("Destination port: %u\n", ntohs(header->dest_prt));
	printf("Verification tag: %x\n", ntohl(header->verif_tag));
	printf("Checksum: 0x%8x\n", ntohl(header->checksum));
}