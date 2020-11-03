#include "application_layout.h"

void
bootp_header_analyze(const u_char *packet)
{
	struct bootphdr *btphdr = (struct bootphdr *)packet;
	print_bootp_op(btphdr->op);
	print_bootp_htype(btphdr->htype);
	print_bootp_hlen(btphdr->hlen);
	printf("Hop count: %u\n", btphdr->hops);
	printf("Transaction ID: 0x%x\n", btphdr->xid);
	printf("Number of seconds: %u\n", btphdr->secs);
	printf("Client IP address: %s\n", inet_ntoa(btphdr->ciaddr));
	printf("Your IP address: %s\n", inet_ntoa(btphdr->yiaddr));
	printf("Server IP address: %s\n", inet_ntoa(btphdr->siaddr));
	printf("Gateway IP address: %s\n", inet_ntoa(btphdr->giaddr));
	print_bootp_chaddr(btphdr->chaddr);
	print_bootp_sname(btphdr->sname);
	print_bootp_file(btphdr->file);
	print_bootp_vendor(btphdr->vend);
}

void
print_bootp_op(uint8_t op)
{
	printf("Opération: ");
	switch (op)
	{
		case BOOTREQUEST:
			puts("Request (1)");
			break;
		case BOOTREPLY:
			puts("Reply (2)");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_bootp_htype(uint8_t htype)
{
	printf("Hardware type: ");
	switch (htype)
	{
	case HTYPE_ETHERNET:
		puts("Ethernet (1)");
		break;
	case HTYPE_EXP_ETHERNET:
		puts("Experimental Ethernet (2)");
		break;
	case HTYPE_IEEE802:
		puts("IEEE802 (6)");
		break;
	case HTYPE_ARCNET:
		puts("ARCnet (6)");
		break;
	default:
		puts("Unknown...");
	}
}

void
print_bootp_hlen(uint8_t hlen)
{
	printf("Hardware address length: %u", hlen);
	if (hlen == 6)
		printf(" (Ethernet)\n");
	else
		puts("");
}

void
print_bootp_chaddr(u_char *chaddr)
{
	(void)chaddr;
}

void
print_bootp_sname(u_char *sname)
{
	(void)sname;
}

void
print_bootp_file(u_char *file)
{
	(void)file;
}

void
print_bootp_vendor(u_char *vend)
{
	(void)vend;
}