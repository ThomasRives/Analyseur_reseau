#include "sctp.h"

void
sctp_analayze(const u_char *packet, uint length)
{
	(void)length;
	struct sctp_hdr *header = (struct sctp_hdr *)packet;
	printf("Source port: %u\n", ntohs(header->src_prt));
	printf("Destination port: %u\n", ntohs(header->dest_prt));
	printf("Verification tag: %x\n", ntohl(header->verif_tag));
	printf("Checksum: 0x%8x\n", ntohl(header->checksum));
	sctp_read_chunks(packet + sizeof(struct sctp_hdr), 
		length - sizeof(struct sctp_hdr));
}

void
sctp_read_chunks(const u_char *packet, uint length)
{
	struct chunck_hdr *ch_hdr;
	uint nb_chunk = 1;

	for (uint pack_off = 0; pack_off < length;
		 pack_off += sizeof(struct chunck_hdr), nb_chunk++)
	{
		ch_hdr = (struct chunck_hdr *)(packet + pack_off);
		printf("Chunk n° %u:\n", nb_chunk);

		print_sctp_chunk(*ch_hdr, packet += sizeof(struct chunck_hdr));

		pack_off += ch_hdr->length;
	}
}

void
print_sctp_chunk(struct chunck_hdr ch_hdr, const u_char *packet)
{
	printf("\tChunk type: ");
	switch(ch_hdr.type)
	{
		case DATA:
			printf("payload data (%u)\n", ch_hdr.type);
			print_sctp_chunck_data(packet);
			break;
		case INIT:
			printf("initialisation (%u)\n", ch_hdr.type);
			print_sctp_chunck_init(packet);
			break;
		case INIT_ACK:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case SACK:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case HEARTBEAT:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case HEARTBEAT_ACK:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case SCTP_ABORT:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case SHUTDOWN:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case SHUTDOWN_ACK:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case ERROR:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case COOKIE_ECHO:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case COOKIE_ACK:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case SHUTDOWN_COMPLETE:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case AUTH:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case I_DATA:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case ASCONF_ACK:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case RE_CONFIG:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case PAD:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case FORWARD_TSN:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case ASCONF:
			printf(" (%u)\n", ch_hdr.type);
			break;
		case I_FORWARD_TSN:
			printf(" (%u)\n", ch_hdr.type);
			break;
		default:
			puts("Unknown type of chunk...");
	}
}

void
print_sctp_chunck_data(const u_char *packet)
{
	struct chunck_hdr *ch_hdr = (struct chunck_hdr *)packet;
	puts("\tFlags:");
	if(ch_hdr->flags & FLAG_I)
		puts("\t\tSACK chunck should be sent back without delay");
	if(ch_hdr->flags & FLAG_U)
		puts("\t\tInvalid sequence number");
	if(ch_hdr->flags & FLAG_B)
		puts("\t\tBeginning fragment");
	if(ch_hdr->flags & FLAG_E)
		puts("\t\tEnd fragment");
	printf("\tLength: %u\n", ch_hdr->length);
	struct data_chunck *dt_ch =
		(struct data_chunck *)(packet + sizeof(struct chunck_hdr));

	printf("\tTransmission Sequence Number: %x", dt_ch->tsn);

	printf("\tStream id: %x", dt_ch->stream_id);
	printf("\tStream sequence number: %x", dt_ch->stream_seq_nb);
	printf("\tPayload protocol id: %x", dt_ch->payload_prot_id);
	printf("\tData payload: ");
	printf_as_str(packet + sizeof(struct chunck_hdr) +
					  sizeof(struct data_chunck),
				  ch_hdr->length  - sizeof(struct data_chunck));
}

void
print_sctp_chunck_init(const u_char *packet)
{
	struct chunck_hdr *ch_hdr = (struct chunck_hdr *)packet;
	printf("\tLength: %u\n", ch_hdr->length);
	struct init_chunck *in_ch = (struct init_chunck *)packet;
	printf("\tInitial tag: %u", in_ch->init_tag);
	printf("\tAdvertised receiver window credit: %u", in_ch->adv_rec_win);
	printf("\tNumber of outbound streams: %u", in_ch->nb_outbound_streams);
	printf("\tNumber of inbound streams: %u", in_ch->nb_inbound_streams);
	printf("\tInitial TSN: %u", in_ch->initial_TSN);

	struct init_chunck_param *param;
	uint param_nb = 1;
	for (uint len = sizeof(struct chunck_hdr) + sizeof(struct init_chunck); len < ch_hdr->length;)
	{
		param = (struct init_chunck_param *)(packet + len);
		const u_char *param_payload = 
			(const u_char *)param + sizeof(struct init_chunck_param);
		printf("\tParam n° %u\n", param_nb);
		printf("\t\tType: ");
		switch(param->type)
		{
			case PARAM_IPV4:
				printf("List all IPv4 addresses (%u)\n", param->type);
				for (uint i = 0; i < param->length; i += sizeof(struct in_addr))
				{
					printf("\t\t%s\n", inet_ntoa(*(struct in_addr *)(param_payload + i)));
				}
				break;
			case PARAM_IPV6:
				printf("List all IPv6 addresses (%u)\n", param->type);
				for (uint i = 0; i < param->length; i += sizeof(struct in_addr))
				{
					char buf_adr[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, param_payload + i, buf_adr,
						INET6_ADDRSTRLEN);
					printf("\t\t%s\n", buf_adr);
				}
				break;
			case PARAM_LIFE_SPAN:
				printf("Suggested life-span increment: (%u)\n", param->type);
				printf("\t\t%u ms\n", *(uint32_t *)(param_payload));
				break;
			case PARAM_HOSTNAME:
				printf("Hostname (%u)\n", param->type);
				printf("%s\n", (char *)param_payload);
				break;
			case PARAM_SUP_ADDR:
				printf("List supported addresses (%u)\n", param->type);
				for(uint i = 0; i < param->length; i += sizeof(uint16_t))
				{
					switch(*(uint32_t *)(param_payload + i))
					{
						case PARAM_IPV4:
							puts("\t\t\tIPv4");
							break;
						case PARAM_IPV6:
							puts("\t\t\tIPv6");
							break;
						case PARAM_HOSTNAME:
							puts("\t\t\tHostname");
							break;
					}
				}
				break;
			case PARAM_CONGEST:
				printf("Explicit congestion notification (%u)\n", param->type);
				break;
			default:
				puts("Unknown param...");
				break;
		}
	}
}