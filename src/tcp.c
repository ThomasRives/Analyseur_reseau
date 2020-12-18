#include "tcp.h"

void
tcp_header_analyze(const u_char *packet, uint length, int verbose)
{
	struct tcphdr *tcp_header = (struct tcphdr *)packet;
	if(verbose == 2)
	{
		printf("Source port: %u\t", ntohs(tcp_header->th_sport));
		printf("Destination port: %u\n", ntohs(tcp_header->th_dport));
	}
	else if(verbose == 3)
	{
		printf("Source port: %u\n", ntohs(tcp_header->th_sport));
		printf("Destination port: %u\n", ntohs(tcp_header->th_dport));
		printf("Sequence number: %u\n", ntohl(tcp_header->th_seq));
		printf("Acknowledge: %u\n", ntohl(tcp_header->th_ack));
		printf("Data offset: %u octets\n", tcp_header->th_off * 4);

		print_tcp_flags(tcp_header->th_flags);

		printf("Window: %u\n", ntohs(tcp_header->th_win));
		printf("Checksum: 0x%x\n", ntohs(tcp_header->th_sum));
		printf("Urgent pointer: %u\n", tcp_header->th_urp);
		uint8_t read_header = sizeof(struct tcphdr);
		uint8_t *tcp_options = (uint8_t *)(packet + read_header);
		print_tcp_options(read_header, tcp_header->th_off, tcp_options);
	}
	uint length_left = length - tcp_header->th_off * 4;
	
	if (length_left > 0)
		demult_port(ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport),
			packet + tcp_header->th_off * 4, length_left, verbose);
	else if(verbose == 1)
		puts("");
}

void
print_tcp_flags(uint8_t flags)
{
	puts("Used flags:");
	if (flags & TH_FIN)
		puts("\tFinish");
	if (flags & TH_SYN)
		puts("\tSynchronize");
	if (flags & TH_RST)
		puts("\tReset");
	if (flags & TH_PUSH)
		puts("\tPush");
	if (flags & TH_ACK)
		puts("\tAck");
	if (flags & TH_URG)
		puts("\tUrgent");
}

void
print_tcp_options(uint8_t read_header, uint8_t off, uint8_t *tcp_options)
{
	while (read_header < off * 4)
	{
		struct tlv next_tlv = tlv_translate_tcp(tcp_options);
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
				printf("Window scale: %i\n", 
					ntohs(*(uint16_t *)(next_tlv.value) & 0x00ff));
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