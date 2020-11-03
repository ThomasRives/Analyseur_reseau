#include "transport_layout.h"
#include "tlv_analyzer.h"

void
tcp_header_analyze(const u_char *packet)
{
	struct tcphdr *tcp_header = (struct tcphdr *)packet;
	printf("Source port: %hu\n", ntohs(tcp_header->th_sport));
	printf("Destination port: %hu\n", ntohs(tcp_header->th_dport));
	printf("Sequence number: %u\n", ntohl(tcp_header->th_seq));
	printf("Acknowledge: %u\n", ntohl(tcp_header->th_ack));
	printf("Data offset: %u octets\n", tcp_header->th_off * 4);

	printf("Used flag:");
	if (tcp_header->th_flags & TH_FIN)
		printf(" Finish");
	if (tcp_header->th_flags & TH_SYN)
		printf(" Synchronize");
	if (tcp_header->th_flags & TH_RST)
		printf(" Reset");
	if (tcp_header->th_flags & TH_PUSH)
		printf(" Push");
	if (tcp_header->th_flags & TH_ACK)
		printf(" Ack");
	if (tcp_header->th_flags & TH_URG)
		printf(" Urgent");
	puts("");

	printf("Window: %hu\n", tcp_header->th_win);
	printf("Checksum: 0x%x\n", ntohs(tcp_header->th_sum));
	printf("Urgent pointer: %hu\n", tcp_header->th_urp);
	uint8_t read_header = sizeof(struct tcphdr);
	uint8_t *tcp_options = (uint8_t *)(packet + read_header);
	print_tcp_options(read_header, tcp_header->th_off, tcp_options);
}

void
print_tcp_options(uint8_t read_header, uint8_t off, uint8_t *tcp_options)
{
	while (read_header < off * 4)
	{
		struct tlv next_tlv = tlv_translate(tcp_options);
		if (next_tlv.type == TCPOPT_EOL || next_tlv.type == TCPOPT_NOP)
		{
			read_header++;
			tcp_options++;
			continue;
		}
		printf("Option: ");
		switch (next_tlv.type)
		{
			case TCPOPT_MAXSEG:
				printf("Maximum segment size: %i\n", *(uint8_t *)(next_tlv.value));
				break;
			case TCPOPT_WINDOW:
				printf("Window scale: %i\n", *(uint16_t *)(next_tlv.value));
				break;
			case TCPOPT_SACK_PERMITTED:
				puts("Segment ACK Permitted");
				break;
			case TCPOPT_SACK:
				puts("Segment Ack");
				break;
			case TCPOPT_TIMESTAMP:
				printf("Timestamps: TSval ");
				print_value_nb((next_tlv.length - 2) / 2, next_tlv.value);
				printf(", TSecr ");
				print_value_nb((next_tlv.length - 2) / 2,
							(next_tlv.value + (next_tlv.length - 2) / 2));
				puts("");
				break;
			default:
				puts("Unsupported");
		}
		free(next_tlv.value);
		read_header += next_tlv.length;
		tcp_options += next_tlv.length;
	}
}

void 
udp_header_analyze(const u_char *packet)
{
	struct udphdr *udp_header = (struct udphdr *)packet;
	printf("Source port: %u\n", ntohs(udp_header->uh_sport));
	printf("Destination port: %u\n", ntohs(udp_header->uh_dport));
	printf("Length: %u\n", ntohs(udp_header->uh_ulen));
	printf("Checksum: 0x%x\n", ntohs(udp_header->uh_sum));
}

void
icmp_header_analyze(const u_char *packet)
{
	struct icmphdr *icmp_header = (struct icmphdr *)packet;

	print_icmp_type_code(icmp_header->type, icmp_header->code);
	printf("Checksum: 0x%x\n", ntohs(icmp_header->checksum));
	printf("Identifier: 0x%x\n", ntohs(icmp_header->un.echo.id));
	printf("Sequence number: %i\n", ntohs(icmp_header->un.echo.sequence));
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
		case 6:
			puts("Alternate Host Address");
			break;
		case ICMP_ECHO:
			puts("Echo Request");
			break;
		case 9:
			puts("Router Advertisement");
			print_icmp_rout_ad_code(code);
			break;
		case 10:
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
		case 40:
			puts("Photuris");
			print_icmp_photuris_code(code);
			break;
		case 41:
			puts("ICMP messages utilized by experimental mobility protocols");
			break;
		case 42:
			puts("Extended Echo Request");
			break;
		case 43:
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
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
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
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
	}
}

void
print_icmp_rout_ad_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case 0:
			puts("Normal router advertisement");
			break;
		case 16:
			puts("Does not route common traffic");
			break;
		default:
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
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
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
	}
}

void
print_icmp_par_prob_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case 0:
			puts("Pointer indicates the error");
			break;
		case ICMP_PARAMPROB_OPTABSENT:
			puts("Missing a Required Option");
			break;
		case 2:
			puts("Bad Length");
			break;
		default:
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
	}
}

void
print_icmp_photuris_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case 0:
			puts("Bad SPI");
			break;
		case 1:
			puts("Authentication Failed");
			break;
		case 2:
			puts("Decompression Failed");
			break;
		case 3:
			puts("Decryption Failed");
			break;
		case 4:
			puts("Need Authentication");
			break;
		case 5:
			puts("Need Authorization");
			break;
		default:
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
	}
}

void
print_icmp_ext_ech_rep_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case 1:
			puts("Malformed Query");
			break;
		case 2:
			puts("No Such Interface");
			break;
		case 3:
			puts("No Such Table Entry");
			break;
		case 4:
			puts("Multiple Interfaces Satisfy Query");
			break;
		default:
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
	}
}

void
icmpv6_header_analyze(const u_char *packet)
{
	struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)packet;
	printf("Type: ");
	switch(icmp6_header->icmp6_type)
	{
		case ICMP6_DST_UNREACH:
			puts("Destination Unreachable");
			print_icmp6_dest_unreach_code(icmp6_header->icmp6_code);
			break;
		case ICMP6_PACKET_TOO_BIG:
			puts("Packet Too Big");
			printf("Code: %i\n", icmp6_header->icmp6_code);
			break;
		case ICMP6_TIME_EXCEEDED:
			puts("Time Exceeded");
			print_icmp6_time_exc_code(icmp6_header->icmp6_code);
			break;
		case ICMP6_PARAM_PROB:
			puts("Parameter Problem");
			print_icmpv6_par_prob_code(icmp6_header->icmp6_code);
			break;
		case ICMP6_INFOMSG_MASK:
			puts("Echo Request");
			break;
		case ICMP6_ECHO_REPLY:
			puts("Echo Reply");
			break;
		case MLD_LISTENER_QUERY:
			puts("Multicast Listener Query");
			break;
		case MLD_LISTENER_REPORT:
			puts("Multicast Listener Report");
			break;
		case MLD_LISTENER_REDUCTION:
			puts("Multicast Listener Done");
			break;
		case ND_ROUTER_SOLICIT:
			puts("Router Solicitation");
			break;
		case ND_ROUTER_ADVERT:
			puts("Router Advertisement");
			break;
		case ND_NEIGHBOR_SOLICIT:
			puts("Neighbor Solicitation");
			break;
		case ND_NEIGHBOR_ADVERT:
			puts("Neighbor Advertisement");
			break;
		case ND_REDIRECT:
			puts("Redirect Message");
			break;
		case ICMP6_ROUTER_RENUMBERING:
			puts("Router Renumbering");
			print_icmpv6_rout_rem_code(icmp6_header->icmp6_code);
			break;
		default:
			puts("Unknown...");
	}
	printf("Checksum: 0x%x\n", ntohs(icmp6_header->icmp6_cksum));
}

void
print_icmp6_dest_unreach_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP6_DST_UNREACH_NOROUTE:
			puts("No route to destination");
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			puts("Communication with destination administratively prohibited");
			break;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			puts("Beyond scope of source address");
			break;
		case ICMP6_DST_UNREACH_ADDR:
			puts("Address unreachable");
			break;
		case ICMP6_DST_UNREACH_NOPORT:
			puts("Bad port");
			break;
		case 5:
			puts("Source address failed ingress/egress policy");
			break;
		case 6:
			puts("Reject route to destination");
			break;
		case 7:
			puts("Error in Source Routing Header");
			break;
		case 8:
			puts("Headers too long");
			break;
		default:
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
	}
}

void
print_icmp6_time_exc_code(uint8_t code)
{
	printf("Code :");
	switch (code)
	{
		case ICMP6_TIME_EXCEED_TRANSIT:
			puts("Hop limit exceeded in transit");
			break;
		case ICMP6_TIME_EXCEED_REASSEMBLY:
			puts("Fragment reassembly time exceeded");
			break;
		default:
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
	}
}

void
print_icmpv6_par_prob_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case ICMP6_PARAMPROB_HEADER:
			puts("Erroneous header field encountered");
			break;
		case ICMP6_PARAMPROB_NEXTHEADER:
			puts("Unrecognized Next Header type encountered");
			break;
		case ICMP6_PARAMPROB_OPTION:
			puts("Unrecognized IPv6 option");
			break;
		case 3:
			puts("IPv6 First Fragment has incomplete IPv6 Header Chain");
			break;
		case 4:
			puts("SR Upper-layer Header Error");
			break;
		case 5:
			puts("Unrecognized Next Header type encountered by intermediate node");
			break;
		case 6:
			puts("Extension header too big");
			break;
		case 7:
			puts("Extension header chain too long");
			break;
		case 8:
			puts("Too many extension headers");
			break;
		case 9:
			puts("Too many options in extension header");
			break;
		case 10:
			puts("Option too big");
			break;
		default:
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
	}
}

void
print_icmpv6_rout_rem_code(uint8_t code)
{
	printf("Code: ");
	switch (code)
	{
		case 0:
			puts("Router Renumbering Command");
			break;
		case 1:
			puts("Router Renumbering Result");
			break;
		case 255:
			puts("Sequence Number Reset");
			break;
		default:
			puts("\b\b\b\b\b\b      \b\b\b\b\b\b");
	}
}

void
demult_port(uint16_t port, const u_char *packet)
{
	printf("Protocole: ");
	switch(port)
	{
	case IPPORT_BOOTPS:
	case IPPORT_BOOTPC:
		bootp_header_analyze(packet);
		break;
	default:
		puts("Unknown...");
	}
}