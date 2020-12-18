#include "transport_layout.h"
#include "tlv_analyzer.h"

void
demult_port(uint16_t port_src, uint16_t port_dst, const u_char *packet, 
	uint length, int verbose)
{
	uint16_t port = port_src;
	if(verbose == 3)
		printf("\nProtocole: ");
	for(uint i = 0; i < 2;port = port_dst, i++)
		switch (port)
		{
			case PORT_BOOTPS:
			case PORT_BOOTPC:
				if(verbose == 1 || verbose == 3)
				{
					print_i_bg_blue("Bootp", 1);
					if(verbose == 1)
						return;
				}
				else
					print_i_bg_blue("Bootp ", 0);
				bootp_analyze(packet, verbose);
				return;
			case PORT_SMTP:
				print_i_bg_purple("SMTP", 1);
				if (verbose != 3)
					return;
				smtp_analyze(packet, length);
				return;
			case PORT_TELNET:
				print_i_bg_white("Telnet", 1);
				if (verbose != 3)
					return;
				telnet_analyze(packet, length);
				return;
			case PORT_FTP:
				print_i_bg_yellow("FTP", 1);
				if (verbose != 3)
					return;
				ftp_analyze(packet, length);
				return;
			case PORT_HTTP:
				print_i_bg_white("Telnet", 1);
				if (verbose != 3)
					return;
				http_analyze(packet, length);
				return;
			case PORT_DNS:
				if (verbose == 1 || verbose == 3)
				{
					print_i_bg_cyan("DNS", 1);
					if (verbose == 1)
						return;
				}
				else
					print_i_bg_cyan("DNS ", 0);
				dns_analyze(packet, verbose);
				return;
			case PORT_POP:
				print_i_bg_black("POP3", 1);
				if (verbose != 3)
					return;
				pop_analyze(packet, length);
				return;
			case PORT_IMAP:
				print_i_bg_red("IMAP", 1);
				if (verbose != 3)
					return;
				imap_analyze(packet, length);
				return;
		}
	puts("Unknown...");
}