#include "dns.h"
#include "utilities.h"

void
dns_analyze(const u_char *packet, int verbose)
{
	struct dnshdr *dns_hdr = (struct dnshdr *)packet;

	if(verbose == 2)
	{
		if ((ntohs(dns_hdr->ctrl) & QR) == QR_QUERY)
			puts("Type: Query");
		else
			puts("Type: Response");
		return;
	}
	printf("Id: %x\n", ntohs(dns_hdr->id));
	dns_print_ctrl(ntohs(dns_hdr->ctrl));

	uint nb_quest = ntohs(dns_hdr->qst_count);
	uint nb_answ = ntohs(dns_hdr->answ_count);
	uint nb_auth = ntohs(dns_hdr->auth_count);
	uint nb_add = ntohs(dns_hdr->add_count);

	printf("Number of question entries: %d\n", nb_quest);
	printf("Number of answer entries: %d\n", nb_answ);
	printf("Number of \"Authority\" entries: %d\n", nb_auth);
	printf("Number of \"additional\" entries: %d\n", nb_add);

	uint index = sizeof(struct dnshdr);

	for(uint i = 0; i < nb_quest; i++)
		index += dns_print_query(packet + index, packet);
		
	for(uint i = 0; i < nb_answ; i++)
		index += dns_print_answer(packet + index, packet);
	
	for(uint i = 0; i < nb_auth; i++)
		index += print_aut_answ(packet + index, packet);
		
	for(uint i = 0; i < nb_add; i++)
		index += print_add_rec(packet + index, packet);
}

void
dns_print_ctrl(uint16_t ctrl)
{
	if((ctrl & QR) == QR_QUERY)
		puts("Type: Query");
	else
		puts("Type: Response");

	dns_type_of_req(ctrl & OPCODE);

	if ((ctrl & QR) != QR_QUERY && (ctrl & AA) == AA)
		puts("Authoritative Answer");
	if((ctrl & TC) == TC)
		puts("Troncated message");
	else
		puts("Not troncate");

	if((ctrl & RD) == RD)
		puts("Ask recursivity");
	if ((ctrl & QR) != QR_QUERY && (ctrl & RA) == RA)
		puts("Recursivity authorized");

	if((ctrl & QR) == QR_QUERY)
		return;

	dns_rcode(ctrl & RCODE);
}

void
dns_type_of_req(uint16_t op)
{
	printf("Type of request: ");
	switch(op)
	{
		case OP_QUERY:
			puts("Standard request");
			break;
		case OP_IQUERY:
			puts("Revert Query");
			break;
		case OP_STATUS:
			puts("Query status");
			break;
		case OP_NOTIFY:
			puts("Notify");
			break;
		case OP_UPDATE:
			puts("Update");
			break;
		case OP_DSO:
			puts("DNS Stateful Operations");
			break;
		default:
			puts("Unknown...");
	}
}

void
dns_rcode(uint16_t rcode)
{
	printf("RCode: ");
	switch(rcode)
	{
		case RC_NE:
			puts("No Error");
			break;
		case RC_FORM_ERR:
			puts("Format Error");
			break;
		case RC_SERV_FAIL:
			puts("Server Failure");
			break;
		case RC_NALE_ERR:
			puts("No such name");
			break;
		case RC_NOT_IMP:
			puts("Not Implemented");
			break;
		case RC_REFUSED:
			puts("Query Refused");
			break;
		case RC_YXD:
			puts("Name Exists when it should not");
			break;
		case RC_YXRRS:
			puts("RR Set Exists when it should not");
			break;
		case RC_NXRRS:
			puts("RR Set that should exist does not");
			break;
		case RC_NA:
			puts("Not Authorized");
			break;
		case RC_NZ:
			puts("Name not contained in zone");
			break;
		case RC_BADVERS:
			puts("Bad OPT Version");
			break;
		case RC_BADKEY:
			puts("Key not recognized");
			break;
		case RC_BADTIME:
			puts("Signature out of time window");
			break;
		case RC_BADMODE:
			puts("Bad TKEY Mode");
			break;
		case RC_BADNAME:
			puts("Duplicate key name");
			break;
		case RC_BADALG:
			puts("Algorithm not supported");
			break;
		case RC_BADTRUNC:
			puts("Bad Truncation");
			break;
		default:
			puts("Unknown...");
	}
}

int
dns_print_query(const u_char *query, const u_char *packet)
{
	printf("Query:\n");
	printf("\tName: ");
	uint byte_read = complete_dns_name(query, UINT16_MAX, packet);
	print_dns_type(ntohs(*(uint16_t *)(query + byte_read)));

	byte_read += sizeof(uint16_t);

	print_dns_class(ntohs(*(uint16_t *)(query + byte_read)));

	return byte_read + sizeof(uint16_t);
}

int
dns_print_answer(const u_char *answ, const u_char *packet)
{
	printf("Answers:\n");
	printf("\tName: ");
	uint byte_read = complete_dns_name(answ, UINT16_MAX, packet);

	uint16_t type = ntohs(*(uint16_t *)(answ + byte_read));
	print_dns_type(type);
	byte_read += sizeof(uint16_t);

	print_dns_class(ntohs(*(uint16_t *)(answ + byte_read)));
	byte_read += sizeof(uint16_t);

	print_hms("\tTTL:", ntohl(*(uint32_t *)(answ + byte_read)));
	byte_read += sizeof(uint32_t);

	uint data_len = ntohs(*(uint16_t *)(answ + byte_read));
	printf("\tData length: %i\n", data_len);
	byte_read += sizeof(uint16_t);

	print_dns_ans_data(type, answ + byte_read, data_len, packet);

	return byte_read + data_len;
}

int
print_aut_answ(const u_char *answ, const u_char *packet)
{
	printf("Authoritative nameserver:\n");
	printf("\tName: ");
	uint byte_read = complete_dns_name(answ, UINT16_MAX, packet);

	uint16_t type = ntohs(*(uint16_t *)(answ + byte_read));
	print_dns_type(type);
	byte_read += sizeof(uint16_t);

	print_dns_class(ntohs(*(uint16_t *)(answ + byte_read)));
	byte_read += sizeof(uint16_t);

	print_hms("\tTTL:", ntohl(*(uint32_t *)(answ + byte_read)));
	byte_read += sizeof(uint32_t);

	uint data_len = ntohs(*(uint16_t *)(answ + byte_read));
	byte_read += sizeof(uint16_t);

	printf("\tData length: %i\n", data_len);

	return byte_read + data_len;
}

int
print_add_rec(const u_char *add_rec, const u_char *packet)
{
	printf("Additional RRs:\n");
	printf("\tName: ");
	uint byte_read = complete_dns_name(add_rec, UINT16_MAX, packet);

	uint16_t type = ntohs(*(uint16_t *)(add_rec + byte_read));
	print_dns_type(type);
	byte_read += sizeof(uint16_t);

	print_dns_class(ntohs(*(uint16_t *)(add_rec + byte_read)));
	byte_read += sizeof(uint16_t);

	print_hms("\tTTL:", ntohl(*(uint32_t *)(add_rec + byte_read)));
	byte_read += sizeof(uint32_t);

	uint data_len = ntohs(*(uint16_t *)(add_rec + byte_read));
	byte_read += sizeof(uint16_t);

	printf("\tData length: %i\n", data_len);

	print_dns_ans_data(type, add_rec + byte_read, data_len, packet);
	return byte_read + data_len;
}

void
print_dns_type(uint16_t type)
{
	printf("\tType: ");
	switch(type)
	{
		case T_A:
			puts("IPv4 address");
			break;
		case T_NS:
			puts("Authoritative name server");
			break;
		case T_MD:
			puts("Mail destination");
			break;
		case T_MF:
			puts("Mail forwarder");
			break;
		case T_CNAME:
			puts("Canonical name");
			break;
		case T_SOA:
			puts("Start of a zone of authority");
			break;
		case T_MB:
			puts("Mailbox domain name");
			break;
		case T_MG:
			puts("Mail group member");
			break;
		case T_MR:
			puts("Mail rename domain name");
			break;
		case T_NULL:
			puts("Null resource record");
			break;
		case T_WKS:
			puts("Well known service description");
			break;
		case T_PTR:
			puts("Domain name ptr");
			break;
		case T_HINFO:
			puts("Host info");
			break;
		case T_MINFO:
			puts("Mailbox or mail list info");
			break;
		case T_MX:
			puts("Mail exchange");
			break;
		case T_TXT:
			puts("Text strings");
			break;
		case T_RP:
			puts("Responsible person");
			break;
		case T_AFSDB:
			puts("AFS Data Base location");
			break;
		case T_X25:
			puts("X.25 PSDN address");
			break;
		case T_ISDN:
			puts("ISDN address");
			break;
		case T_RT:
			puts("Route Throught");
			break;
		case T_NSAP:
			puts("NSAP address");
			break;
		case T_SIG:
			puts("Security signature");
			break;
		case T_KEY:
			puts("Security key");
			break;
		case T_PX:
			puts("X.400 mail mapping information");
			break;
		case T_GPOS:
			puts("Geographical Position");
			break;
		case T_AAAA:
			puts("IPv6 address");
			break;
		case T_LOC:
			puts("Location Information");
			break;
		case T_NXT:
			puts("Next domain");
			break;
		case T_EID:
			puts("Endpoint Id");
			break;
		case T_NIMLOC:
			puts("Nimrod locator");
			break;
		case T_SRV:
			puts("Server location");
			break;
		case T_ATMA:
			puts("ATM Address");
			break;
		case T_NAPTR:
			puts("Naming Authority Pointer");
			break;
		case T_KX:
			puts("Key Exchanger");
			break;
		case T_A6:
			puts("Adresse IPv6");
			break;
		case T_DNAME:
			puts("Delegation Name");
			break;
		case T_OPT:
			puts("EDNS");
			break;
		case T_DS:
			puts("Delegation Signer");
			break;
		case T_SSHFP:
			puts("SSH Key Fingerprint");
			break;
		case T_RRSIG:
			puts("DNSSEC");
			break;
		case T_NSEC:
			puts("Next SECure");
			break;
		case T_DNSKEY:
			puts("DNSSEC");
			break;
		case T_DHCID:
			puts("DHCP id");
			break;
		case T_NSEC3:
			puts("DNSSEC");
			break;
		case T_NSEC3PARAM:
			puts("DNSSEC");
			break;
		case T_HIP:
			puts("Host Id Protocol");
			break;
		case T_TALINK:
			puts("Trust Anchor LINK");
			break;
		case T_CDS:
			puts("Child DS");
			break;
		case T_SPF:
			puts("Sender Policy Framework");
			break;
		case T_TSIG:
			puts("Transaction Signature");
			break;
		case T_IXFR:
			puts("Incremental transfer");
			break;
		case T_AXFR:
			puts("A request for a transfer of an entire zone");
			break;
		case T_MAILB:
			puts("A request for mailbox-related records");
			break;
		case T_MAILA:
			puts("A request for mail agent RRs");
			break;
		case T_ALL:
			puts("A request for all records");
			break;
		case T_CAA:
			puts("Certification Authority Authorization");
			break;
		case T_DNSSECTA:
			puts("Trust Authorities");
			break;
		case T_DNSSECLV:
			puts("Lookaside Validation");
			break;
		default:
			puts("Unknown...");
	}
}

void
print_dns_class(uint16_t class)
{
	printf("\tClass: ");
	switch (class)
	{
		case CL_RESERVED:
			puts("Reserved");
			break;
		case CL_IN:
			puts("Internet");
			break;
		case CL_CSNET:
			puts("Csnet");
			break;
		case CL_CH:
			puts("Chaos");
			break;
		case CL_HS:
			puts("Hesiod");
			break;
		case CL_ANY:
			puts("QCLASS only");
			break;
		default:
			puts("Unknown...");
	}
}

uint
complete_dns_name(const u_char *name, uint name_len, const u_char *packet)
{
	uint byte_r;
	uint next_point;
	for(byte_r = 0; byte_r < name_len && name[byte_r] != '\0';)
	{
		if (name_len - byte_r >= 2)
		{
			uint16_t ptr_name = ntohs((*(uint16_t *)(name + byte_r)));
			if((ptr_name & PT_N) == PT_N)
			{
				complete_dns_name(packet + (ptr_name & N_DECL), 
					UINT16_MAX, packet);
				return byte_r + sizeof(uint16_t);
			}
		}

		next_point = name[byte_r];

		printf("%.*s", next_point, name + byte_r + sizeof(uint8_t));

		printf(".");
		byte_r += sizeof(uint8_t) + next_point;
	}
	puts("\b ");
	return byte_r + sizeof(uint8_t);
}

void
print_dns_ans_data(uint16_t type, const u_char *data, uint16_t data_len, const u_char *packet)
{
	uint16_t txt_len;
	char buf_adr[INET6_ADDRSTRLEN];
	uint32_t ipv4_addr;
	switch (type)
	{
		case T_A:
			ipv4_addr = ntohl(*(uint32_t *)data);
			printf("\tIPv4 address: ");
			for(uint i = 0; i < 4; i++)
				printf("%u.", (ipv4_addr >> (8* (3 - i))) & 0xff);
			printf("\b \n");
			break;
		case T_NS:
			printf("\tName server: ");
			complete_dns_name(data, data_len, packet);
			break;
		case T_CNAME:
			printf("\tCNAME (Canonical Name): ");
			complete_dns_name(data, data_len, packet);
			break;
		case T_PTR:
			printf("\tDomain name: ");
			complete_dns_name(data, data_len, packet);
			break;
		case T_MX:
			printf("\tPreference: %u\n", ntohs(*(uint16_t *)data));
			printf("\tMail Exchange: ");
			complete_dns_name(data + sizeof(uint16_t), 
				data_len - sizeof(uint16_t), packet);
			break;
		case T_TXT:
			txt_len = *(uint8_t *)data;
			printf("\tTXT length: %i\n", txt_len);
			printf("\tText: %.*s\n", txt_len, data + sizeof(uint8_t));
			break;
		case T_AAAA:
			inet_ntop(AF_INET6, (void *)data, buf_adr, INET6_ADDRSTRLEN);
			printf("\tIPv6 Address: %s\n", buf_adr);
			break;
	}
}
