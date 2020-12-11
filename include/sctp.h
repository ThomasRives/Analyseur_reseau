#ifndef SCTP_H
#define SCTP_H
#include "application_layout.h"

#define FLAG_I 0x08 /* SACK chunk should be sent back without delay */
#define FLAG_U 0x04 /* unordered chunk */
#define FLAG_B 0x02 /* beginning fragment */
#define FLAG_E 0x01 /* end fragment */

/* Chunks */
#define DATA 0	/* Payload data */
#define INIT 1	/* Initiation */
#define INIT_ACK 2	/* Initiation acknowledgement */
#define SACK 3	/* Selective acknowledgement */
#define HEARTBEAT 4	/* Heartbeat request */
#define HEARTBEAT_ACK 5	/* Heartbeat acknowledgement */
#define SCTP_ABORT 6	/* Abort */
#define SHUTDOWN 7	/* Shutdown */
#define SHUTDOWN_ACK 8	/* Shutdown acknowledgement */
#define ERROR 9	/* Operation error */
#define COOKIE_ECHO 10	/* State cookie */
#define COOKIE_ACK 11	/* Cookie acknowledgement */
#define SHUTDOWN_COMPLETE 14	/* Shutdown complete */
#define AUTH 15	/* Authentication chunk */
#define I_DATA 64	/* Payload data supporting packet interleaving */
#define ASCONF_ACK 128	/* Address configuration change acknowledgement */
#define RE_CONFIG 130	/* Stream reconfiguration */
#define PAD 132	/* Packet padding */
#define FORWARD_TSN 192	/* Increment expected TSN */
#define ASCONF 193	/* Address configuration change */
#define I_FORWARD_TSN 194	
/* Increment expected TSN, supporting packet interleaving */ 

/**
 * @brief This structure represent the header of a SCTP
 * packet (it does not include the chunks)
 */
struct sctp_hdr {
	uint16_t src_prt;   /**<Source port */
	uint16_t dest_prt;	/**<Destination port */
	uint32_t verif_tag; /**<Verification tag*/
	uint32_t checksum;	/**<Checksum */
};

/**
 * @brief This structure represent the header of an SCTP chunck.
 */
struct chunck_hdr {
	uint8_t type;		/**< Type of the chunck */
	uint8_t flags;		/**< flags of the chunck */
	uint16_t length;	/**< length of the chunck */
};

struct init_chunck {
	uint32_t init_tag;
	uint32_t adv_rec_win;
	uint16_t nb_outbound_streams;
	uint16_t nb_inbound_streams;
	uint32_t initial_TSN;
};

#define PARAM_IPV4 5
#define PARAM_IPV6 6
#define PARAM_LIFE_SPAN 9
#define PARAM_HOSTNAME 11
#define PARAM_SUP_ADDR 12
#define PARAM_CONGEST 32768

struct sack_chunk {
	uint32_t cumultiv_tsn_ack;
	uint32_t adv_rec_win;
	uint16_t nb_gap_ack;
	uint16_t nb_dup_tsn;
};

struct heartbeat_chunk {
	struct tlv tlv;
};

struct heartbeat_chunk_ack {
	struct tlv tlv;
};

struct abort_chunk {
	uint32_t error_causes;
};

struct shutdown_chunk {
	uint32_t cumultiv_tsn_ack;
};

#define SEND_ID 1
#define SEND_REC_INIT 2
#define SEND_REC_COOKIE 3
#define SEND_OUT_RESS 4
#define ADDR_NOT_RES 5
#define UNREC_CHUNK 6
#define MANDAT_PARAM 7
#define INIT_ACK_ORIGINATOR 8
#define DATA_NO_USER 9
#define SEND_REC_COOK_ECH 10

struct auth_chunk {
	uint16_t shared_key_id;
	uint16_t hmac_id;
	uint8_t *hmac;
};

struct asconf_ack_chunk {
	uint32_t seq_numb;
};

struct re_config_chunk
{
	uint8_t *param1;
	/* It is possible to have more than 1 parameter */
};

struct out_req_param {
	uint16_t param_type;
	uint16_t param_len;
	uint32_t req_seq_numb;
	uint32_t resp_seq_numb;
	uint32_t send_last_tsn;
};

struct in_req_param {
	uint32_t req_seq_numb;
};

struct reset_req_param {
	uint32_t req_seq_nb;
};

struct reconf_resp_param {
	uint32_t resp_seq_nb;
	uint32_t res;
};

/* Result code */
#define S_NTD 0 /* Success - Nothing to do */
#define S_PERF 1 /* Success - Performed */
#define DENIED 2
#define WRONG_SSN 3 /* Error - Wrong SSN */
#define REQ_IN_PROG 4 /* Error - Request already in progress */
#define BAD_SEQ_NUMB 5 /* Error - Bad Sequence Number */
#define IN_PROG 6	   /* In progress */

struct add_out_req_param {
	uint32_t req_seq_nb;
	uint16_t nb_new_stream;
	uint16_t reserved;
};

struct add_in_req_param {
	uint32_t req_seq_nb;
	uint16_t nb_new_stream;
	uint16_t reserved;
};

struct data_chunk {
	uint32_t tsn;
	uint16_t stream_id;
	uint16_t reserved;
	uint32_t msg_id;
	uint32_t prot_id;
	uint8_t *data;
};

struct forward_tsn_chunk_mod {
	uint32_t new_cum_tsn;
	/* Streams ids */
};

struct asconf_chunk {
	uint32_t seq_nb;
	uint16_t param_type;
	uint16_t param_len;
	uint32_t ip_addr;
	/* asconfs param */
};

struct forward_tsn_chunk {
	uint32_t cumul_tsn;
};

struct stream_res_msg_id {
	uint16_t stream_id;
	uint16_t reserved; /* last bit not used */
	uint32_t msg_id;
};

/**
 * @brief Analyze the SCTP part of the packet
 * 
 * @param packet: the packet himself.
 * @param length: the length of the packet.
 */
void sctp_analayze(const u_char *packet, uint length);

#endif //SCTP_H