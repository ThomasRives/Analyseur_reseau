#include "sctp.h"

void
sctp_analayze(const u_char *packet, uint length, int verbose)
{
	struct sctp_hdr *header = (struct sctp_hdr *)packet;
	if(verbose == 2)
	{
		print_sctp_chunk(packet + sizeof(struct sctp_hdr), 1);
		return;
	}
	
	printf("Source port: %u\n", ntohs(header->src_prt));
	printf("Destination port: %u\n", ntohs(header->dest_prt));
	printf("Verification tag: 0x%x\n", ntohl(header->verif_tag));
	printf("Checksum: 0x%8x\n", ntohl(header->checksum));
	sctp_read_chunks(packet + sizeof(struct sctp_hdr), 
		length - sizeof(struct sctp_hdr));
}

void
sctp_read_chunks(const u_char *packet, uint length)
{
	uint nb_chunk = 1;

	for (uint pack_off = 0; pack_off < length;
		 pack_off += sizeof(struct chunk_hdr), nb_chunk++)
	{
		struct chunk_hdr *ch_hdr = (struct chunk_hdr *)(packet + pack_off);
		uint chunk_len = ntohs(ch_hdr->length); 
		if(chunk_len == 0)//to stop because it's a padding.
			break;
		printf("Chunk n° %u:\n", nb_chunk);
		printf("\t\t");
		pack_off +=  print_sctp_chunk(packet + pack_off, 0);
	}
}

uint
print_sctp_chunk(const u_char *packet, int first_only)
{
	struct chunk_hdr *ch_hdr = (struct chunk_hdr *)packet;
	uint chunk_len = ntohs(ch_hdr->length);//to stop because it's a padding.
	
	printf("Chunk type: ");
	switch(ch_hdr->type)
	{
		case DATA:
			puts("payload data (0)");
			if (first_only)
				return 0;
			print_sctp_chunk_data(packet);
			break;
		case INIT:
			puts("initialisation (1)");
			if(first_only)
				return 0;
			print_sctp_chunk_init(packet);
			break;
		case INIT_ACK:
			puts("Initialization ACK (2)");
			if(first_only)
				return 0;
			print_sctp_chunk_init_ack(packet);
			break;
		case SACK:
			puts("Selective acknowledgment (3)");
			if(first_only)
				return 0;
			print_sctp_chunk_sack(packet);
			break;
		case HEARTBEAT:
			puts("Heartbeat (4)");
			if (first_only)
				return 0;
			print_sctp_chunk_heartbeat(packet);
			break;
		case HEARTBEAT_ACK:
			puts("Heartbeat ACK (5)");
			if (first_only)
				return 0;
			print_sctp_chunk_ack_heartbeat(packet);
			break;
		case SCTP_ABORT:
			puts("Abort (6)");
			if(first_only)
				return 0;
			if (ch_hdr->flags & FLAG_T)
				puts("\t\tSender sent Verification Tag");
			printf("\t\tLength: %u\n", chunk_len);
			printf("\t\tError cause(s): 0x%x\n", ntohl(*(uint32_t *)packet));
			break;
		case SHUTDOWN:
			puts("Shutdown (7)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			packet += sizeof(struct chunk_hdr);
			printf("\t\tLast TSN received: %u\n", ntohl(*(uint32_t *)packet));
			break;
		case SHUTDOWN_ACK:
			puts("Shutdown ACK (8)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case CHUNK_ERROR:
			puts("ERROR (9)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case COOKIE_ECHO:
			puts("Cookie echo (10)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			print_as_str(packet, chunk_len - sizeof(uint32_t));
			break;
		case COOKIE_ACK:
			puts("Cookie ACK (11)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case SHUTDOWN_COMPLETE:
			puts("Shutdown complete (14)");
			if (first_only)
				return 0;
			if(ch_hdr->flags & FLAG_T)
				puts("\t\tSender didn't have a TCB");
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case AUTH:
			puts("Authentification chunk (15)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case I_DATA:
			puts("Interleaving data (64)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case ASCONF_ACK:
			puts("address reconfiguration ACK (128)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case RE_CONFIG:
			puts("Reconfiguration  (130)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case PAD:
			puts("Padding (132)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case FORWARD_TSN:
			puts("Forward TSN (192)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case ASCONF:
			puts("Address reconfiguration (193)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		case I_FORWARD_TSN:
			puts("Forward TSN with support for interleaving (194)");
			if (first_only)
				return 0;
			printf("\t\tLength: %u\n", chunk_len);
			break;
		default:
			puts("Unknown type of chunk...");
	}
	return chunk_len;
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

	printf("\tTransmission Sequence Number: %u\n", ntohl(dt_ch->tsn));

	printf("\tStream id: %x\n", dt_ch->stream_id);
	printf("\tStream sequence number: %u\n", ntohs(dt_ch->stream_seq_nb));
	printf("\tPayload protocol id: %u\n", ntohl(dt_ch->payload_prot_id));
	puts("\tData payload:");
	print_as_str(packet + sizeof(struct chunk_hdr) +
					 sizeof(struct data_chunk),
				 ntohs(ch_hdr->length) - sizeof(struct chunk_hdr) - 
				 	sizeof(struct data_chunk));
	puts("");
}

void
print_sctp_chunk_init(const u_char *packet)
{
	struct chunk_hdr *ch_hdr = (struct chunk_hdr *)packet;
	uint hdr_len = ntohs(ch_hdr->length);
	printf("\tLength: %u\n", hdr_len);
	struct init_chunk *in_ch = 
		(struct init_chunk *)(packet + sizeof(struct chunk_hdr));
	printf("\tInitial tag: %u\n", in_ch->init_tag);
	printf("\tAdvertised receiver window credit: %u\n", in_ch->adv_rec_win);
	printf("\tNumber of outbound streams: %u\n", in_ch->nb_outbound_streams);
	printf("\tNumber of inbound streams: %u\n", in_ch->nb_inbound_streams);
	printf("\tInitial TSN: %u\n", in_ch->initial_TSN);

	struct init_chunk_param *param;
	uint param_nb = 1;
	const u_char *param_payload = (const u_char *)
		packet + sizeof(struct chunk_hdr) + sizeof(struct init_chunk_param);
	
	for (uint len = sizeof(struct chunk_hdr) + sizeof(struct init_chunk);
		 len < hdr_len;)
	{
		param = (struct init_chunk_param *)(packet + len);
		printf("\tParam n° %u\n", param_nb);
		uint param_len = ntohs(param->length);
		uint param_type = ntohs(param->type);
		uint data_beg = 2 * sizeof(uint16_t);
		printf("\t\tLength: %u\n", param_len);
		printf("\t\tType: ");
		switch(param_type)
		{
			case PARAM_IPV4:
				printf("List all IPv4 addresses (%u):\n", param_type);
				printf("\t\tLength: %u\n", param_len);
				for (uint i = data_beg; i < param_len;
					i += sizeof(uint32_t))
				{
					printf("\t\t%s\n", inet_ntoa(*(struct in_addr *)
						((u_char *)param + i)));
				}
				break;
			case PARAM_IPV6:
				printf("List all IPv6 addresses (%u):\n", param_type);
				for (uint i = data_beg; i < param_len;
					i += sizeof(struct in_addr))
				{
					char buf_adr[INET6_ADDRSTRLEN];
					uint32_t addr = ntohl(*(uint32_t *)(param_payload + i));
					inet_ntop(AF_INET6, &addr, buf_adr,
							  INET6_ADDRSTRLEN);
					printf("\t\t%s\n", buf_adr);
				}
				break;
			case PARAM_COOKIE:
				puts("Cookie sent (%u)\n");
				print_hex(param_payload, param_len);
				break;
			case PARAM_LIFE_SPAN:
				printf("Suggested life-span increment (%u):\n", param_type);
				printf("\t\t%u ms\n", *(uint32_t *)(param_payload));
				break;
			case PARAM_HOSTNAME:
				printf("Hostname (%u)\n", param_type);
				printf("%s\n", (char *)param_payload);
				break;
			case PARAM_SUP_ADDR:
				printf("List supported addresses (%u):\n", param_type);
				for (uint i = data_beg; i < param_len; i += sizeof(uint16_t))
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
				printf("Explicit congestion notification (%u)\n", param_type);
				break;
			default:
				puts("Unknown param...");
				break;
		}
		len += param_len;
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
	printf("\tLength: %u\n", ntohs(ch_hdr->length));
	struct sack_chunk *sa_ch = (struct sack_chunk *)
		(packet + sizeof(struct chunk_hdr));
	printf("\tCumulative TSN ACK: %u\n", ntohl(sa_ch->cumultiv_tsn_ack));
	printf("\tAdvertised receiver window credit: %u\n", 
		ntohl(sa_ch->adv_rec_win));
	printf("\tNumber of gap ACK blocks: %u\n", ntohs(sa_ch->nb_gap_ack));
	printf("\tNumber of duplicate TSNs: %u\n", ntohs(sa_ch->nb_dup_tsn));
	const u_char *gap_ack = (const u_char *)
		(packet + sizeof(struct chunk_hdr) + sizeof(struct sack_chunk));

	for (uint i = 0; i < sa_ch->nb_gap_ack; i += 2)
	{
		printf("\tGap ACK block n° %u start: %u\n", i + 1,
			*(gap_ack + (i * sizeof(uint16_t))));
		printf("\tGap ACK block n° %u end: %u\n", i + 1,
			*(gap_ack + (i * sizeof(uint16_t) + sizeof(uint8_t))));
	}

	const u_char *dup_tsn = (const u_char *)
		(gap_ack + sa_ch->nb_gap_ack * sizeof(uint16_t));

	for (uint i = 0, j = 1; i < sa_ch->nb_dup_tsn; i += sizeof(uint32_t), j++)
		printf("\tDuplicate TSN n° %u: %u\n", j, *(dup_tsn + i));
}

void
print_sctp_chunk_heartbeat(const u_char *packet)
{
	struct chunk_hdr *ch_hdr = (struct chunk_hdr *)packet;
	printf("\tLength: %u\n", ntohs(ch_hdr->length));
	struct heartbeat_chunk *hb_ch = (struct heartbeat_chunk *)
		(packet + sizeof(struct chunk_hdr));
	uint heart_len = ntohs(hb_ch->length);
	puts("\tParameter type: heartbeat info (1)");
	printf("\t\tLength: %u\n", heart_len);
	puts("\t\tHeartbeat info:");
	print_hex(
		packet + sizeof(struct chunk_hdr) + sizeof(struct heartbeat_chunk), heart_len - 2 * sizeof(uint16_t));
}

void
print_sctp_chunk_ack_heartbeat(const u_char *packet)
{
	struct chunk_hdr *ch_hdr = (struct chunk_hdr *)packet;
	printf("\tLength: %u\n", ntohs(ch_hdr->length));
	struct heartbeat_chunk_ack *hb_ch = (struct heartbeat_chunk_ack *)
		(packet + sizeof(struct chunk_hdr));
	puts("\tParameter type: heartbeat ack (1)");
	uint hb_len = ntohs(hb_ch->length);
	printf("\tLength: %u\n", hb_len);
	puts("\tHeartbeat info:");
	print_hex(
		packet + sizeof(struct chunk_hdr) + sizeof(struct heartbeat_chunk),
			hb_len - 2 * sizeof(uint16_t)
		);
}