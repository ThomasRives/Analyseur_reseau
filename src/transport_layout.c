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
	printf("Type: ");
	switch (icmp_header->type)
	{
		case ICMP_ECHOREPLY:
			puts("Echo Reply");
			break;
		case ICMP_DEST_UNREACH:
			puts("Destination Unreachable");
			break;
		case ICMP_SOURCE_QUENCH:
			puts("Source Quench");
			break;
		case ICMP_REDIRECT:
			puts("Redirect (change route)");
			break;
		case ICMP_ECHO:
			puts("Echo Request");
			break;
		case ICMP_TIME_EXCEEDED:
			puts("Time Exceeded");
			break;
		case ICMP_PARAMETERPROB:
			puts("Parameter Problem");
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
		default:
			puts("Unknown...");
	}
	printf("Code: ");
	switch(icmp_header->code)
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
	printf("Checksum: 0x%x\n", ntohs(icmp_header->checksum));
	printf("Identifier: 0x%x\n", ntohs(icmp_header->un.echo.id));
	printf("Sequence number: %i\n", ntohs(icmp_header->un.echo.sequence));
}