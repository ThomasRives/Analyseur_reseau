#ifndef SCTP_H
#define SCTP_H
#include "transport_layout.h"

#define PORT_SCTP 443


#define FLAG_I 0x08 /* SACK chunk should be sent back without delay */
#define FLAG_U 0x04 /* unordered chunk */
#define FLAG_B 0x02 /* beginning fragment */
#define FLAG_E 0x01 /* end fragment */
#define FLAG_T 0x80 /* end fragment */

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
#define CHUNK_ERROR 9	/* Operation error */
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
} __attribute__((packed));

/**
 * @brief This structure represent the header of an SCTP chunck.
 */
struct chunk_hdr {
	uint8_t type;		/**< Type of the chunck */
	uint8_t flags;		/**< flags of the chunck */
	uint16_t length;	/**< length of the chunck */
} __attribute__((packed));

struct data_chunk {
	uint32_t tsn;
	uint16_t stream_id;
	uint16_t stream_seq_nb;
	uint32_t payload_prot_id;
} __attribute__((packed));

struct init_chunk {
	uint32_t init_tag;
	uint32_t adv_rec_win;
	uint16_t nb_outbound_streams;
	uint16_t nb_inbound_streams;
	uint32_t initial_TSN;
} __attribute__((packed));

struct init_chunk_param {
	uint16_t type;
	uint16_t length;
} __attribute__((packed));

#define PARAM_IPV4 5
#define PARAM_IPV6 6
#define PARAM_COOKIE 7
#define PARAM_LIFE_SPAN 9
#define PARAM_HOSTNAME 11
#define PARAM_SUP_ADDR 12
#define PARAM_CONGEST 32768

struct sack_chunk {
	uint32_t cumultiv_tsn_ack;
	uint32_t adv_rec_win;
	uint16_t nb_gap_ack;
	uint16_t nb_dup_tsn;
} __attribute__((packed));

struct heartbeat_chunk {
	uint16_t param_type;
	uint16_t length;
} __attribute__((packed));

struct heartbeat_chunk_ack {
	uint16_t param_type;
	uint16_t length;
	u_char *info;
} __attribute__((packed));

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

/**
 * @brief Analyze the SCTP part of the packet
 * 
 * @param packet: the packet himself.
 * @param length: the length of the packet.
 */
void sctp_analayze(const u_char *packet, uint length);

/**
 * @brief Read the chunks of an sctp packet
 * 
 * @param packet: the packet himself (beggin at the first chunk).
 * @param length: the length of the packet.
 */
void sctp_read_chunks(const u_char *packet, uint length);

/**
 * @brief Print the content of a sctp chunk.
 * 
 * @param packet: : the packet himself (beggin at the first chunk).
 * @return the size of the read chunk.
 */
uint print_sctp_chunk(const u_char *packet);

/**
 * @brief Print the content of a data chunk.
 * 
 * @param packet: the packet himself (beggin at the chunk).
 */
void print_sctp_chunk_data(const u_char *packet);

/**
 * @brief Print the content of an initialisation chunk.
 * 
 * @param packet: the packet himself (beggin at the chunk).
 */
void print_sctp_chunk_init(const u_char *packet);

/**
 * @brief Print the content of a initialisation ACK chunk.
 * 
 * @param packet: the packet himself (beggin at the chunk).
 */
void print_sctp_chunk_init_ack(const u_char *packet);

/**
 * @brief Print the content of a SACK chunk.
 * 
 * @param packet: the packet himself (beggin at the chunk).
 */
void print_sctp_chunk_sack(const u_char *packet);

/**
 * @brief Print the content of a heartbeat chunk.
 * 
 * @param packet: the packet himself (beggin at the chunk).
 */
void print_sctp_chunk_heartbeat(const u_char *packet);

/**
 * @brief Print the content of an heartbeat ACK.
 * 
 * @param packet: the packet himself (beggin at the chunk).
 */
void print_sctp_chunk_ack_heartbeat(const u_char *packet);

#endif //SCTP_H