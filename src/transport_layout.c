#include "transport_layout.h"
#include "tlv_analyzer.h"

void
demult_port(uint16_t port_src, uint16_t port_dst, const u_char *packet, uint length)
{
	uint16_t port = port_src;
	printf("\nProtocole: ");
	for(uint i = 0; i < 2;port = port_dst, i++)
		switch (port)
		{
			case PORT_BOOTPS:
			case PORT_BOOTPC:
				print_i_bg_blue("Bootp", 1);
				bootp_analyze(packet);
				return;
			case PORT_SMTP:
				print_i_bg_purple("SMTP", 1);
				smtp_analyze(packet, length);
				return;
			case PORT_TELNET:
				print_i_bg_white("Telnet", 1);
				telnet_analyze(packet, length);
				return;
			case PORT_FTP:
				print_i_bg_yellow("FTP", 1);
				ftp_analyze(packet, length);
				return;
			case PORT_HTTP:
				print_i_bg_green("HTTP", 1);
				http_analyze(packet, length);
				return;
			case PORT_DNS:
				print_i_bg_cyan("DNS", 1);
				dns_analyze(packet);
				return;
			case PORT_POP:
				print_i_bg_black("POP3", 1);
				pop_analyze(packet, length);
				return;
			case PORT_IMAP:
				print_i_bg_red("IMAP", 1);
				imap_analyze(packet, length);
				return;
		}
		
	puts("Unknown...");
}