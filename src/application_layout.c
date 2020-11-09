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
	printf_as_str(packet, length);
	puts("");
}

void
ftp_analyze(const u_char *packet, uint length)
{
	for(uint i = 0; i < length;)
	{
		if( i >= length - 3)
		{
			printf("%c%c", packet[i], packet[i + 1]);
			break;
		}

		if(!is_digit(packet[i]) ||
			(i + 1 < length && !is_digit(packet[i + 1])) ||
			(i + 2 < length && !is_digit(packet[i + 2]))
		)
		{
			i += print_until_rn(&packet[i]);
			continue;
		}

		printf_ftp_command(&packet[i]);
		i += print_until_rn(&packet[i]);
	}
}

void
telnet_analyze(const u_char *packet, uint length)
{
	if(length == 0)
		return;
	uint i = 0;
	if (packet[0] != IAC)
	{
		printf("Option data: ");
		for (; i < length && packet[i] != IAC; i++)
			printf("%c", packet[i]);

		puts("");
	}
	i++;

	for (; i < length; i++)
	{
		print_telnet_command(packet[i]);
		if(++i >= length)
			return;
		print_telnet_suboption(packet[i]);

		if(++i >= length)
			return;
		else if(packet[i] == IAC)
			continue;

		printf("\tOption data: ");
		for (; i < length && packet[i] != IAC; i++)
			printf("%2.x",packet[i]);

		puts("");
	}
}

void
http_analyze(const u_char *packet, uint length)
{
	printf_as_str(packet, length);
	puts("");
}