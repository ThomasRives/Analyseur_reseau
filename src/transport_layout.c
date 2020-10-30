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
	int read_header = sizeof(sizeof(struct tcphdr));
	uint8_t *tcp_options = (uint8_t *)(packet + read_header);
	while(read_header < tcp_header->th_off)
	{
		struct tlv next_tlv = tlv_translate(tcp_options);
		if (next_tlv.type == TCPOPT_EOL || next_tlv.type == TCPOPT_NOP)
			continue;
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
				printf("Timestamps %ul\n",*(uint16_t *)(next_tlv.value));
				break;
			default:
				puts("Unsupported");
		}
		free(next_tlv.value);
		read_header += next_tlv.length;
		tcp_options += next_tlv.length;
	}

}