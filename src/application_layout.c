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
	for(uint i = 0; i < length; i++)
	{
		if(packet[i] != 0xff)//data
		{
			//TODO
			continue;
		}

		switch(packet[i])//INSTR
		{
			case OPT_EOL:
				puts("");
				break;//!!!!
			case OPT_BIN_TRANS:
				puts("");
				break;//!!!!!!
			case OPT_ECHO:
				puts("");
				break;//!!!!!
			case OPT_RECONNEXION:
				puts("");
				break;//!!!
			case OPT_SUP_GO_AHEAD:
				puts("");
				break;//!!!!
			case OPT_MSG_SIZE_NEG:
				puts("");
				break;
			case OPT_STATUS:
				puts("");
				break;//!!!!!!!!!!!!!!!!!!!!!!!!!!!
			case OPT_TIMING_MASK:
				puts("");
				break;//!!!!!!!!!!!!!!!!!
			case OPT_REMOTE_CTR:
				puts("");
				break;
			case OPT_OUT_LINE_W:
				puts("");
				break;
			case OPT_OUT_PG_SIZE:
				puts("");
				break;
			case OPT_OUT_CARR_RET_DISP:
				puts("");
				break;
			case OPT_OUT_HOR_TAB_STOP:
				puts("");
				break;
			case OPT_OUT_HOR_TAB_DISP:
				puts("");
				break;
			case OPT_OUT_FORMFEED:
				puts("");
				break;
			case OPT_OUT_VERT_TAB_STOP:
				puts("");
				break;
			case OPT_OUT_VERT_TAB_DISP:
				puts("");
				break;
			case OPT_OUT_LINEFEED_DISP:
				puts("");
				break;
			case OPT_EXTENDED_ASCII:
				puts("");
				break;
			case OPT_LOGOUT:
				puts("");
				break;
			case OPT_BYTE_MACR:
				puts("");
				break;
			case OPT_DATA_ENT_TERM:
				puts("");
				break;
			case OPT_SUPDUP:
				puts("");
				break;
			case OPT_SUPDUP_OUT:
				puts("");
				break;
			case OPT_SEND_LOC:
				puts("");
				break;
			case OPT_TERM_TYPE:
				puts("");
				break;
			case OPT_END_REC:
				puts("");
				break;
			case OPT_TACACS:
				puts("");
				break;
			case OPT_OUT_MARK:
				puts("");
				break;
			case OPT_TERM_LOC_NB:
				puts("");
				break;
			case OPT_TELNET_3270:
				puts("");
				break;
			case OPT_X3_PAD:
				puts("");
				break;
			case OPT_NEG_WIN_SIZE:
				puts("");
				break;
			case OPT_TERM_SPEED:
				puts("");
				break;
			case OPT_REM_FLOW_CTRL:
				puts("");
				break;
			case OPT_LINEMODE:
				puts("");
				break;//!!!!!!!!!!!
			case OPT_X_DISP_LOC:
				puts("");
				break;
			case OPT_ENV_OPT:
				puts("");
				break;
			case OPT_AUTH_OPT:
				puts("");
				break;
			case OPT_ENC_OPT:
				puts("");
				break;
			case OPT_NEW_ENV_OPT:
				puts("");
				break;
			case OPT_TN3270E:
				puts("");
				break;
			case OPT_XAUTH:
				puts("");
				break;
			case OPT_CHARSET:
				puts("");
				break;
			case OPT_TRSP:
				puts("");
				break;
			case OPT_CPCO:
				puts("");
				break;
			case OPT_TSLE:
				puts("");
				break;
			case OPT_TSTLS:
				puts("");
				break;
			case OPT_KERMIT:
				puts("");
				break;
			case OPT_SEND_URL:
				puts("");
				break;
			case OPT_FORWARD_X:
				puts("");
				break;
			case OPT_TPL:
				puts("");
				break;
			case OPT_TSSPIL:
				puts("");
				break;
			case OPT_TPRAGMAH:
				puts("");
				break;
		}
	}
}