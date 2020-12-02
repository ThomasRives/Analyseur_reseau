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
	printf_as_str(packet, length);
	puts("");
}

void
telnet_analyze(const u_char *packet, uint length)
{
	if(length == 0)
		return;
	uint i = 0;
	if (packet[0] != IAC)
	{
		printf("Data: ");
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

void
dns_analyze(const u_char *packet, uint length)
{
	(void)length;
	uint index = 0;
	struct dnshdr *dns_hdr = (struct dnshdr *)packet;
	printf("Id: %x\n", ntohs(dns_hdr->id));
	print_dns_ctrl(dns_hdr->ctrl);
	uint nb_quest = ntohs(dns_hdr->qst_count);
	uint nb_answ = ntohs(dns_hdr->answ_count);
	uint nb_auth = ntohs(dns_hdr->auth_count);
	uint nb_add = ntohs(dns_hdr->add_count);
	printf("Number of question entries: %d\n", nb_quest);
	printf("Number of answer entries: %d\n", nb_answ);
	printf("Number of \"Authority\" entries: %d\n", nb_auth);
	printf("Number of \"additional\" entries: %d\n", nb_add);

	index += sizeof(struct dnshdr);
	for(uint i = 0; i < nb_quest; i++)
		index += print_dns_query(packet + index, packet);
		
	for(uint i = 0; i < nb_answ; i++)
		index += print_dns_answer(packet + index, packet);
	
	for(uint i = 0; i < nb_auth; i++)
		index += print_aut_answ(packet + index, packet);
}

void
pop_analyze(const u_char *packet, uint length)
{
	printf_as_str(packet, length);
	puts("");
}

void
imap_analyze(const u_char *packet, uint length)
{
	printf_as_str(packet, length);
	puts("");
}