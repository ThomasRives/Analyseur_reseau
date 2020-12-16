#include "transport_layout.h"
#include "tlv_analyzer.h"

void
demult_port(uint16_t port_src, uint16_t port_dst, const u_char *packet, uint length)
{
	uint16_t port = port_src;
	printf("Protocole: ");
	for(uint i = 0; i < 2;port = port_dst, i++)
		switch (port)
		{
			case PORT_BOOTPS:
			case PORT_BOOTPC:
				puts("Bootp");
				bootp_analyze(packet);
				return;
			case PORT_SMTP:
				puts("SMTP");
				smtp_analyze(packet, length);
				return;
			case PORT_TELNET:
				puts("Telnet");
				telnet_analyze(packet, length);
				return;
			case PORT_FTP:
				puts("FTP");
				ftp_analyze(packet, length);
				return;
			case PORT_HTTP:
				puts("HTTP");
				http_analyze(packet, length);
				return;
			case PORT_DNS:
				puts("DNS");
				dns_analyze(packet, length);
				return;
			case PORT_POP:
				puts("POP3");
				pop_analyze(packet, length);
				return;
			case PORT_IMAP:
				puts("IMAP");
				imap_analyze(packet, length);
				return;
		}
		
	puts("Unknown...");
}