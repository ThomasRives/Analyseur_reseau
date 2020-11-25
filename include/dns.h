#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

/* QR */
#define QR_QUERY 0
#define QR_REP 1

/* Opcode */
#define OP_QUERY 0
#define OP_IQUERY 1
#define OP_STATUS 2
#define OP_NOTIFY 4
#define OP_UPDATE 5
#define OP_DSO 6

#define AA_ 1 /* Authoritative Answer */
#define TC_ 1 /* Truncated */
#define RD_ 1 /* Recursion Desired */
#define RA_ 1 /* Recursion Available */
#define Z_ 1 /* Zeros */
#define AD_ 1 /* Authenticated data */
#define CD_ 1 /* Checking Disabled */

/* Return Code */
#define RC_NE 0 /* No error */
#define RC_FORM_ERR 1 /* Format Error */
#define RC_SERV_FAIL 2 /* Server Failure */
#define RC_NALE_ERR 3 /* Name Error */
#define RC_NOT_IMP 4 /* Not Implemented */
#define RC_REFUSED 5 /* Refused */
#define RC_YXD 6 /* YXDomain */
#define RC_YXRRS 7 /* YXRRS */
#define RC_NXRRS 8 /* NXRRSet */
#define RC_NA 9 /* Not Auth */
#define RC_NZ 10 /* Not Zone */
#define RC_BADVERS 16
#define RC_BADKEY 17
#define RC_BADTIME 18
#define RC_BADMODE 19
#define RC_BADNAME 20
#define RC_BADALG 21
#define RC_BADTRUNC 22

/* Type of query or resource record */
#define T_A 1 /* IPv4 address */
#define T_NS 2 /* Authoritative name server */
#define T_MD 3 /* Mail destination */
#define T_MF 4 /* Mail forwarder */
#define T_CNAME 5 /* Canonical name */
#define T_SOA 6	  /* Start of a zone of authority */
#define T_MB 7 /* Mailbox domain name */
#define T_MG 8 /* Mail group member */
#define T_MR 9 /* Mail rename domain name */
#define T_NULL 10 /* Null resource record */
#define T_WKS 11 /* Well known service description */
#define T_PTR 12 /* Domain name ptr */
#define T_HINFO 13 /* Host info */
#define T_MINFO 14 /* Mailbox or mail list info */
#define T_MX 15 /* Mail exchange */
#define T_TXT 16 /* Text strings */
#define T_RP 17 /* Responsible person */
#define T_AFSDB 18 /* AFS Data Base location */
#define T_X25 19 /* X.25 PSDN address */
#define T_ISDN 20 /* ISDN address */
#define T_RT 21 /* Route Throught */
#define T_NSAP 22 /* NSAP address */
#define T_SIG 24 /* Security signature */
#define T_KEY 25 /* Security key */
#define T_PX 26	 /* X.400 mail mapping information */
#define T_GPOS 27 /* Geographical Position */
#define T_AAAA 28 /* IPv6 address */
#define T_LOC 29 /* Location Information */
#define T_NXT 30 /* Next domain */
#define T_EID 31 /* Endpoint Id */
#define T_NIMLOC 32 /* Nimrod locator */
#define T_SRV 33 /* Server location */
#define T_ATMA 34 /* ATM Address */
#define T_NAPTR 35 /* Naming Authority Pointer */
#define T_KX 36 /* Key Exchanger */
#define T_A6 38
#define T_DNAME 39
#define T_OPT 41
#define T_DS 43 /* Delegation Signer */
#define T_SSHFP 44 /* SSH Key Fingerprint */
#define T_RRSIG 46
#define T_NSEC 47 /* Next SECure */
#define T_DNSKEY 48
#define T_DHCID 49 /* DHCP id */
#define T_NSEC3 50
#define T_NSEC3PARAM 51
#define T_HIP 55 /* Host Id Protocol */
#define T_TALINK 58 /* Trust Anchor LINK */
#define T_CDS 59 /* Child DS */
#define T_SPF 99 /* Sender Policy Framework */
#define T_TSIG 250 /* Transaction Signature */
#define T_IXFR 251 /* Incremental transfer */
#define T_AXFR 252 /* A request for a transfer of an entire zone */
#define T_MAILB 253 /* A request for mailbox-related records */
#define T_MAILA 254 /* A request for mail agent RRs */
#define T_ALL 255 /* A request for all records */
#define T_CAA 257 /* Certification Authority Authorization */
#define T_DNSSECTA 32768 /* Trust Authorities */
#define T_DNSSECLV 32769 /* Lookaside Validation */

/* Class */
#define CL_RESERVED 0
#define CL_IN 1 /* Internet */
#define CL_CH 3 /* Chaos */
#define CL_HS 4 /* Hesiod */
#define CL_ANY 255 /* QCLASS only */

/* Flags */
#define QR 0x8000
#define OPCODE 0x7800
#define AA 0x0400
#define TC 0x0200
#define RD 0x0100
#define RA 0x0080
#define Z 0x0070
#define RCODE 0x000f

/* Pointer name */
#define PT_N 0xc000
#define PT_N2 0xc0
#define N_DECL 0x3fff


/**
 * @brief Describe the header of DNS packet.
 */
struct dnshdr {
	uint16_t id; /**< Identitification */
	uint16_t ctrl; /**< Control */
	uint16_t qst_count; /**< Question count */
	uint16_t answ_count; /**< Answer count */
	uint16_t auth_count; /**< Authorithy count */
	uint16_t add_count; /**< Additional count */
};

/**
 * @brief Decribe ressource record format.
 */
struct ressource_record {
	uint8_t *name; /**< Name of the query */
	uint16_t type; /**< Type of the query */
	uint16_t classe; /**< Class */
	uint32_t TTL; /**< Time To Live */
	uint16_t Rdata_length; /**< Length of the data */
	uint8_t *Rdata; /**< The data itself */
};

/**
 * @brief Describe query format.
 */
struct query {
	uint8_t *query_name; /**< The name of the query */
	uint16_t type; /**< Type of the query */
	uint16_t classe; /**< Classe of the query */
};

/**
 * @brief Describe a SOA
 */
struct soa {
	uint32_t serial; /**< The serial number */
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t min_ttl;
};

/**
 * @brief Print the control informations of a DNS packet.
 * 
 * @param ctrl: the control bits.
 */
void print_dns_ctrl(uint16_t ctrl);

/**
 * @brief Print a name in a dns packet.
 * 
 * @param query: the query to read.
 * @param packet: the packet.
 * @return length read.
 */
int print_dns_name(const u_char *query, const u_char *packet);

/**
 * @brief Print a query in a dns packet.
 * 
 * @param query: the query to read.
 * @param packet: the packet.
 * @return lentgh of the query.
 */
int print_dns_query(const u_char *query, const u_char *packet);

/**
 * @brief Print an answer in a dns packet.
 * 
 * @param query: the query to read.
 * @param packet: the packet.
 * @return the length of the answer.
 */
int print_dns_answer(const u_char *query, const u_char *packet);

/**
 * @brief Print the type as a DNS type.
 * 
 * @param type: the type to print.
 */
void print_dns_type(uint16_t type);

/**
 * @brief Print the class as a DNS class.
 * 
 * @param class: the class to print.
 */
void print_dns_class(uint16_t class);

/**
 * @brief Print the DNS data (depends of type).
 * 
 * @param type: the type of the answer.
 * @param data: a pointer to the data to print.
 * @param data_len: the length of the data.
 * @param packet: the DNS packet.
 */
void print_dns_ans_data(uint16_t type, const u_char *data, uint16_t data_len, const u_char *packet);

#endif //DNS_H