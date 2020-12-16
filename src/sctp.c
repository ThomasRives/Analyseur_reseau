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
	struct chunk_hdr *ch_hdr;
	uint nb_chunk = 1;

	for (uint pack_off = 0; pack_off < length;
		 pack_off += sizeof(struct chunk_hdr), nb_chunk++)
	{
		ch_hdr = (struct chunk_hdr *)(packet + pack_off);
		printf("Chunk n° %u:\n", nb_chunk);

		print_sctp_chunk(*ch_hdr, packet += sizeof(struct chunk_hdr));

		pack_off += ch_hdr->length;
	}
}

void
print_sctp_chunk(struct chunk_hdr ch_hdr, const u_char *packet)
{
	printf("\tChunk type: ");
	switch(ch_hdr.type)
	{
		case DATA:
			puts("payload data (0)");
			print_sctp_chunk_data(packet);
			break;
		case INIT:
			puts("initialisation (1)");
			print_sctp_chunk_init(packet);
			break;
		case INIT_ACK:
			puts("Initialization ACK (2)");
			print_sctp_chunk_init_ack(packet);
			break;
		case SACK:
			puts("Heartbeat chunk (3)");
			print_sctp_chunk_sack(packet);
			break;
		case HEARTBEAT:
			puts("Heartbeat (4)");
			print_sctp_chunk_heartbeat(packet);
			break;
		case HEARTBEAT_ACK:
			puts("Heartbeat ack (5)");
			print_sctp_chunk_ack_heartbeat(packet);
			break;
		case SCTP_ABORT:
			puts("Abort (6)");
			if (ch_hdr.flags & FLAG_T)
				puts("\t\tSender sent Verification Tag");
			printf("\t\tLength: %u\n", ch_hdr.length);
			printf("\t\tError cause(s): %x\n", *(uint32_t *)packet);
			break;
		case SHUTDOWN:
			puts("Shutdown (7)");
			printf("\t\tLength: %u\n", ch_hdr.length);
			printf("\t\tLast TSN received: %x", *(uint32_t *)packet);
			break;
		case SHUTDOWN_ACK:
			puts("Shutdown ACK (8)");
			printf("\t\tLength: %u\n", ch_hdr.length);
			break;
		case CHUNK_ERROR:
			puts(" (9)");
			printf("\t\tLength: %u\n", ch_hdr.length);
			//TODO
			break;
		case COOKIE_ECHO:
			puts("Cookie echo (10)");
			printf("\t\tLength: %u\n", ch_hdr.length);
			print_as_str(packet, ch_hdr.length - sizeof(uint32_t));
			break;
		case COOKIE_ACK:
			puts("Cookie ACK (11)");
			printf("\t\tLength: %u\n", ch_hdr.length);
			break;
		case SHUTDOWN_COMPLETE:
			puts("Shutdown complete (14)");
			if(ch_hdr.flags & FLAG_T)
				puts("\t\tSender didn't have a TCB");
			printf("\t\tLength: %u\n", ch_hdr.length);
			break;
		case AUTH:
			puts("Authentification chunk (15)");
			break;
		case I_DATA:
			puts("Interleaving data (64)");
			break;
		case ASCONF_ACK:
			puts("address reconfiguration ACK (128)");
			break;
		case RE_CONFIG:
			puts("Reconfiguration  (130)");
			break;
		case PAD:
			puts("Padding (132)");
			break;
		case FORWARD_TSN:
			puts("Forward TSN (192)");
			break;
		case ASCONF:
			puts("Address reconfiguration (193)");
			break;
		case I_FORWARD_TSN:
			puts("Forward TSN with support for interleaving (194)");
			break;
		default:
			puts("Unknown type of chunk...");
	}
}

void
print_sctp_chunk_data(const u_char *packet)
{
	struct chunk_hdr *ch_hdr = (struct chunk_hdr *)packet;
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
	struct data_chunk *dt_ch =
		(struct data_chunk *)(packet + sizeof(struct chunk_hdr));

	printf("\tTransmission Sequence Number: %x", dt_ch->tsn);

	printf("\tStream id: %x", dt_ch->stream_id);
	printf("\tStream sequence number: %x", dt_ch->stream_seq_nb);
	printf("\tPayload protocol id: %x", dt_ch->payload_prot_id);
	printf("\tData payload: ");
	print_as_str(packet + sizeof(struct chunk_hdr) +
					  sizeof(struct data_chunk),
				  ch_hdr->length  - sizeof(struct data_chunk));
}

void
print_sctp_chunk_init(const u_char *packet)
{
	struct chunk_hdr *ch_hdr = (struct chunk_hdr *)packet;
	printf("\tLength: %u\n", ch_hdr->length);
	struct init_chunk *in_ch = 
		(struct init_chunk *)(packet + sizeof(struct chunk_hdr));
	printf("\tInitial tag: %u", in_ch->init_tag);
	printf("\tAdvertised receiver window credit: %u", in_ch->adv_rec_win);
	printf("\tNumber of outbound streams: %u", in_ch->nb_outbound_streams);
	printf("\tNumber of inbound streams: %u", in_ch->nb_inbound_streams);
	printf("\tInitial TSN: %u", in_ch->initial_TSN);

	struct init_chunk_param *param;
	uint param_nb = 1;
	const u_char *param_payload = 
		(const u_char *)param + sizeof(struct init_chunk_param);
	for (uint len = sizeof(struct chunk_hdr) + sizeof(struct init_chunk); 
		len < ch_hdr->length;)
	{
		param = (struct init_chunk_param *)(packet + len);
		printf("\tParam n° %u\n", param_nb);
		printf("\t\tLength: %u\n", param->length);
		printf("\t\tType: ");
		switch(param->type)
		{
			case PARAM_IPV4:
				printf("List all IPv4 addresses (%u):\n", param->type);
				printf("\t\tLength: %u\n", param->length);
				for (uint i = 0; i < param->length; i += sizeof(struct in_addr))
				{
					printf("\t\t%s\n", inet_ntoa(*(struct in_addr *)(param_payload + i)));
				}
				break;
			case PARAM_IPV6:
				printf("List all IPv6 addresses (%u):\n", param->type);
				for (uint i = 0; i < param->length; i += sizeof(struct in_addr))
				{
					char buf_adr[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, param_payload + i, buf_adr,
						INET6_ADDRSTRLEN);
					printf("\t\t%s\n", buf_adr);
				}
				break;
			case PARAM_COOKIE:
				puts("Cookie sent (%u)\n");
				print_hex(param_payload,param->length);
				break;
			case PARAM_LIFE_SPAN:
				printf("Suggested life-span increment (%u):\n", param->type);
				printf("\t\t%u ms\n", *(uint32_t *)(param_payload));
				break;
			case PARAM_HOSTNAME:
				printf("Hostname (%u)\n", param->type);
				printf("%s\n", (char *)param_payload);
				break;
			case PARAM_SUP_ADDR:
				printf("List supported addresses (%u):\n", param->type);
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

void
print_sctp_chunk_init_ack(const u_char *packet)
{
	print_sctp_chunk_init(packet);
}

void
print_sctp_chunk_sack(const u_char *packet)
{
	struct chunk_hdr *ch_hdr = (struct chunk_hdr *)packet;
	printf("\tLength: %u\n", ch_hdr->length);
	struct sack_chunk *sa_ch = (struct sack_chunk *)
		(packet + sizeof(struct chunk_hdr));
	printf("\tCumulative TSN ACK: %u\n", sa_ch->cumultiv_tsn_ack);
	printf("\tAdvertised receiver window credit: %u\n", sa_ch->adv_rec_win)
	printf("\tNumber of gap ACK blocks: %u\n", sa_ch->nb_gap_ack);
	printf("\tNumber of duplicate TSNs: %u\n", sa_ch->nb_dup_tsn);
	const u_char *gap_ack = (const u_char *)
		(packet + sizeof(struct chunk_hdr) + sizeof(struct sack_chunk));

	for (uint i = 0; i < sa_ch->nb_gap_ack; i += 2)
	{
		printf("\tGap ACK block n° %u start: %u\n", i + 1,
			gap_ack + (i * sizeof(uint16_t)));
		printf("\tGap ACK block n° %u end: % u\n", i + 1,
			gap_ack + ((i + 1) * sizeof(uint16_t)));
	}

	const u_char *dup_tsn = (const u_char *)
		(gap_ack + sa_ch->nb_gap_ack * sizeof(uint16_t));

	for(uint i = 0; i < sa_ch->nb_dup_tsn; i++)
	{
		printf("\tDuplicate TSN n° %u: %u\n", i + 1,
			dup_tsn + i * sizeof(uint32_t));
	}
}

void
print_sctp_chunk_heartbeat(const u_char *packet)
{
	struct chunk_hdr *ch_hdr = (struct chunk_hdr *)packet;
	printf("\tLength: %u\n", ch_hdr->length);
	struct heartbeat_chunk *hb_ch = (struct heartbeat_chunk *)
		(packet + sizeof(struct chunk_hdr));
	puts("\tParameter type: heartbeat info (1)");
	printf("\tLength: %u\n", hb_ch->length);
	puts("\tHeartbeat info:");
	print_hex(hb_ch->info, hb_ch->length);
}

void
print_sctp_chunk_ack_heartbeat(const u_char *packet)
{
	struct chunk_hdr *ch_hdr = (struct chunk_hdr *)packet;
	printf("\tLength: %u\n", ch_hdr->length);
	struct heartbeat_chunk_ack *hb_ch = (struct heartbeat_chunk_ack *)
		(packet + sizeof(struct chunk_hdr));
	puts("\tParameter type: heartbeat ack (1)");
	printf("\tLength: %u\n", hb_ch->length);
	puts("\tHeartbeat info:");
	print_hex(hb_ch->info, hb_ch->length);
}