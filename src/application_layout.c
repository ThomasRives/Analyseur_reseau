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
	u_char *content = malloc(sizeof(u_char) * (length + 1));
	NULL_CHECK(content);
	NULL_CHECK(memcpy(content, packet, length));
	content[length] = '\0';
	printf("%s", content);
	free(content);
}

void
telnet_analyze(const u_char *packet, uint length)
{
	uint i = 0;
	printf("%x\n", ntohs(*(uint16_t *)packet));
	if (packet[0] != IAC)
	{
		printf("Option data: ");
		for (; i < length && packet[i] != IAC; i++)
			printf("%.2x", packet[i]);

		puts("");
	}
	i++;

	for (; i < length; i++)
	{
		printf("Suboption ");
		switch(packet[i])
		{
			case IAC:
				printf("Interpret as command");
				break;
			case DONT:
				printf("You are not to use option");
				break;
			case DO:
				printf("Please, you use option");
				break;
			case WONT:
				printf("I won't use option");
				break;
			case WILL:
				printf("I will use option");
				break;
			case SB:
				printf("Interpret as subnegotiation");
				break;
			case GA:
				printf("You may reverse the line");
				break;
			case EL:
				printf("Erase the current line");
				break;
			case EC:
				printf("Erase the current character");
				break;
			case AYT:
				printf("Are you there");
				break;
			case AO:
				printf("Abort output--but let prog finish");
				break;
			case IP:
				printf("Interrupt process--permanently");
				break;
			case BREAK:
				printf("Break");
				break;
			case DM:
				printf("Data mark--for connect");
				break;
			case NOP:
				printf("Nop");
				break;
			case SE:
				printf("End sub negotiation");
				break;
			case EOR:
				printf("End of record");
				break;
			case ABORT:
				printf("Abort process");
				break;
			case SUSP :
				printf("Suspend process");
				break;
			case xEOF:
				printf("End of file: EOF is already used...");
				break;
		}
		printf("\t");
		i++;
		switch(packet[i])
		{
			case TELOPT_BINARY:
				printf("8-bit data path");
				break;
			case TELOPT_ECHO:
				printf("Echo");
				break;
			case TELOPT_RCP:
				printf("Prepare to reconnect");
				break;
			case TELOPT_SGA:
				printf("Suppress go ahead");
				break;
			case TELOPT_NAMS:
				printf("Approximate message size");
				break;
			case TELOPT_STATUS:
				printf("Give status");
				break;
			case TELOPT_TM :
				printf("Timing mark");
				break;
			case TELOPT_RCTE:
				printf("Remote controlled transmission and echo");
				break;
			case TELOPT_NAOL:
				printf("Negotiate about output line width");
				break;
			case TELOPT_NAOP:
				printf("Negotiate about output page size");
				break;
			case TELOPT_NAOCRD:
				printf("Negotiate about CR disposition");
				break;
			case TELOPT_NAOHTS:
				printf("Negotiate about horizontal tabstops");
				break;
			case TELOPT_NAOHTD:
				printf("Negotiate about horizontal tab disposition");
				break;
			case TELOPT_NAOFFD:
				printf("Negotiate about formfeed disposition");
				break;
			case TELOPT_NAOVTS:
				printf("Negotiate about vertical tab stops");
				break;
			case TELOPT_NAOVTD:
				printf("Negotiate about vertical tab disposition");
				break;
			case TELOPT_NAOLFD:
				printf("Negotiate about output LF disposition");
				break;
			case TELOPT_XASCII:
				printf("Extended ascii character set");
				break;
			case TELOPT_LOGOUT:
				printf("Force logout");
				break;
			case TELOPT_BM:
				printf("Byte macro");
				break;
			case TELOPT_DET:
				printf("Data entry terminal");
				break;
			case TELOPT_SUPDUP:
				printf("Supdup protocol");
				break;
			case TELOPT_SUPDUPOUTPUT:
				printf("Supdup output");
				break;
			case TELOPT_SNDLOC:
				printf("Send location");
				break;
			case TELOPT_TTYPE:
				printf("Terminal type");
				break;
			case TELOPT_EOR:
				printf("End or record");
				break;
			case TELOPT_TUID:
				printf("TACACS user identification");
				break;
			case TELOPT_OUTMRK:
				printf("Output marking");
				break;
			case TELOPT_TTYLOC:
				printf("Terminal location number");
				break;
			case TELOPT_3270REGIME:
				printf("3270 regime");
				break;
			case TELOPT_X3PAD:
				printf("X.3 PAD");
				break;
			case TELOPT_NAWS:
				printf("Window size");
				break;
			case TELOPT_TSPEED:
				printf("Terminal speed");
				break;
			case TELOPT_LFLOW:
				printf("Remote flow control");
				break;
			case TELOPT_LINEMODE:
				printf("Linemode option");
				break;
			case TELOPT_XDISPLOC:
				printf("X Display Location");
				break;
			case TELOPT_OLD_ENVIRON:
				printf("Old - Environment variables");
				break;
			case TELOPT_AUTHENTICATION:
				printf("Authenticate");
				break;
			case TELOPT_ENCRYPT:
				printf("Encryption option");
				break;
			case TELOPT_NEW_ENVIRON:
				printf("New - Environment variables");
				break;
			case TELOPT_EXOPL:
				printf("Extended-options-list");
				break;
		}
		
		printf(" (%i)\n", packet[i]);
		i++;

		if(packet[i] == IAC)
			continue;

		printf("\tOption data: ");
		for (; i < length && packet[i] != IAC; i++)
			printf("%2.x",packet[i]);

		puts("");
	}
}