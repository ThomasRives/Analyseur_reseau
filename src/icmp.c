#include "icmp.h"

void
icmp_header_analyze(const u_char *packet)
{
	struct icmphdr *icmp_header = (struct icmphdr *)packet;

	print_icmp_type_code(icmp_header->type, icmp_header->code);
	printf("Checksum: 0x%x\n", ntohs(icmp_header->checksum));
	printf("Identifier: 0x%x\n", icmp_header->un.echo.id);
	printf("Sequence number: %i\n", ntohs(icmp_header->un.echo.sequence));

	char buf[100] = {0};
	struct tm ts;
	time_t time = *(uint32_t *)(packet + sizeof(struct icmphdr));
	ts = *localtime(&time);
	strftime(buf, sizeof(buf), "%Y %m %d %H:%M:%S %Z", &ts);
	printf("Timestamps: %s\n", buf);
}

void
print_icmp_type_code(uint8_t type, uint8_t code)
{
	printf("Type: ");
	switch (type)
	{
		case ICMP_ECHOREPLY:
			puts("Echo Reply");
			break;
		case ICMP_DEST_UNREACH:
			puts("Destination Unreachable");
			print_icmp_dest_unreach_code(code);
			break;
		case ICMP_SOURCE_QUENCH:
			puts("Source Quench");
			break;
		case ICMP_REDIRECT:
			puts("Redirect (change route)");
			print_icmp_dest_unreach_code(code);
			break;
		case ICMP_ALTER_HOST_ADDR:
			puts("Alternate Host Address");
			break;
		case ICMP_ECHO:
			puts("Echo Request");
			break;
		case ICMP_ROUTER_ADV:
			puts("Router Advertisement");
			print_icmp_rout_ad_code(code);
			break;
		case ICMP_ROUT_SOLICI:
			puts("Router Solicitation");
			break;
		case ICMP_TIME_EXCEEDED:
			puts("Time Exceeded");
			print_icmp_time_exc_code(code);
			break;
		case ICMP_PARAMETERPROB:
			puts("Parameter Problem");
			print_icmp_par_prob_code(code);
			break;
		case ICMP_TIMESTAMP:
			puts("Timestamp Request");
			break;
		case ICMP_TIMESTAMPREPLY:
			puts("Timestamp Reply");
			break;
		case ICMP_INFO_REQUEST:
			puts("Information Request");
			break;
		case ICMP_INFO_REPLY:
			puts("Information Reply");
			break;
		case ICMP_ADDRESS:
			puts("Address Mask Request");
			break;
		case ICMP_ADDRESSREPLY:
			puts("Address Mask Reply");
			break;
		case ICMP_PHOTURIS:
			puts("Photuris");
			print_icmp_photuris_code(code);
			break;
		case ICMP_EXP:
			puts("ICMP messages utilized by experimental mobility protocols");
			break;
		case ICMP_EXT_ECHO:
			puts("Extended Echo Request");
			break;
		case ICMP_EXT_ECHO_REP:
			puts("Extended Echo Reply");
			print_icmp_ext_ech_rep_code(code);
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmp_dest_unreach_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP_NET_UNREACH:
			puts("Network Unreachable");
			break;
		case ICMP_HOST_UNREACH:
			puts("Host Unreachable");
			break;
		case ICMP_PROT_UNREACH:
			puts("Protocol Unreachable");
			break;
		case ICMP_PORT_UNREACH:
			puts("Port Unreachable");
			break;
		case ICMP_FRAG_NEEDED:
			puts("Fragmentation Needed");
			break;
		case ICMP_SR_FAILED:
			puts("Source Route failed");
			break;
		case ICMP_NET_UNKNOWN:
			puts("Destination Network Unknown");
			break;
		case ICMP_HOST_UNKNOWN:
			puts("Destination Host Unknown");
			break;
		case ICMP_HOST_ISOLATED:
			puts("Source Host Isolated");
			break;
		case ICMP_NET_ANO:
			puts("Communication with Destination Network is"
				" Administratively Prohibited");
			break;
		case ICMP_HOST_ANO:
			puts("Communication with Destination Host is"
				" Administratively Prohibited");
			break;
		case ICMP_NET_UNR_TOS:
			puts("Destination Network Unreachable for Type of Service");
			break;
		case ICMP_HOST_UNR_TOS:
			puts("Destination Host Unreachable for Type of Service");
			break;
		case ICMP_PKT_FILTERED:
			puts("Communication Administratively Prohibited");
			break;
		case ICMP_PREC_VIOLATION:
			puts("Host Precedence Violation");
			break;
		case ICMP_PREC_CUTOFF:
			puts("Precedence cutoff in effect");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmp_redirect_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP_REDIR_NET:
			puts("Redirect Datagram for the Network");
			break;
		case ICMP_REDIR_HOST:
			puts("Redirect Datagram for the Host");
			break;
		case ICMP_REDIR_NETTOS:
			puts("Redirect Datagram for the Type of Service and Network");
			break;
		case ICMP_REDIR_HOSTTOS:
			puts("Redirect Datagram for the Type of Service and Host");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmp_rout_ad_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP_NORM_ROUT_ADV:
			puts("Normal router advertisement");
			break;
		case ICMP_NOT_ROUT_COMMON_TRAF:
			puts("Does not route common traffic");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmp_time_exc_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP_EXC_TTL:
			puts("Time to Live exceeded in Transit");
			break;
		case ICMP_EXC_FRAGTIME:
			puts("Fragment Reassembly Time Exceeded");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmp_par_prob_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP_PARAMPROB_POINT_ERR:
			puts("Pointer indicates the error");
			break;
		case ICMP_PARAMPROB_OPTABSENT:
			puts("Missing a Required Option");
			break;
		case ICMP_PARAMPROB_BADLEN:
			puts("Bad Length");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmp_photuris_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP_PHOT_BAD_PSI:
			puts("Bad SPI");
			break;
		case ICMP_PHOT_AUTH_FAIL:
			puts("Authentication Failed");
			break;
		case ICMP_PHOT_DECOMP_FAIL:
			puts("Decompression Failed");
			break;
		case ICMP_PHOT_DECRYP_FAIL:
			puts("Decryption Failed");
			break;
		case ICMP_PHOT_NEED_AUTHENT:
			puts("Need Authentication");
			break;
		case ICMP_PHOT_NEED_AUTHORIZ:
			puts("Need Authorization");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_icmp_ext_ech_rep_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP_EER_MALFORMED_REQ:
			puts("Malformed Query");
			break;
		case ICMP_EER_NO_INT:
			puts("No Such Interface");
			break;
		case ICMP_EER_NO_TABLE:
			puts("No Such Table Entry");
			break;
		case ICMP_EER_MULT_INT:
			puts("Multiple Interfaces Satisfy Query");
			break;
		default:
			puts("Unknown...");
	}
}