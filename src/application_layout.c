#include "application_layout.h"

void
bootp_analyze(const u_char *packet)
{
	struct bootphdr *btphdr = (struct bootphdr *)packet;
	uint options_size = bootp_option_length(packet + sizeof(struct bootphdr));
	u_char *vend = malloc(options_size * sizeof(u_char));
	memcpy(vend, packet + sizeof(struct bootphdr), options_size);
	printf("OPT LENGTH: %i\n", options_size);
	print_bootp_op(btphdr->op);
	print_bootp_htype(btphdr->htype);
	print_bootp_hlen(btphdr->hlen);
	printf("Hop count: %u\n", btphdr->hops);
	printf("Transaction ID: 0x%x\n", ntohl(btphdr->xid));
	printf("Seconds elapsed: %u\n", ntohs(btphdr->secs));
	printf("Client IP address: %s\n", inet_ntoa(btphdr->ciaddr));
	printf("Your IP address: %s\n", inet_ntoa(btphdr->yiaddr));
	printf("Server IP address: %s\n", inet_ntoa(btphdr->siaddr));
	printf("Gateway IP address: %s\n", inet_ntoa(btphdr->giaddr));
	print_bootp_chaddr(btphdr->chaddr, btphdr->hlen);
	printf("Server name: ");
	print_bootp_str(btphdr->sname, sizeof(btphdr->sname));
	printf("File name: ");
	print_bootp_str(btphdr->file, sizeof(btphdr->file));
	print_bootp_vendor(vend);
	free(vend);
}

void
smtp_analyze(const u_char *packet, uint length)
{
	for(uint i = 0; i < length; i++)
		printf("%c", *(packet + i));
}