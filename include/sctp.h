#ifndef SCTP_H
#define SCTP_H
#include "application_layout.h"

#define FLAG_I 0x08 /* SACK chunk should be sent back without delay */
#define FLAG_U 0x04 /* unordered chunk */
#define FLAG_B 0x02 /* beginning fragment */
#define FLAG_E 0x01 /* end fragment */

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

/**
 * @brief Analyze the SCTP part of the packet
 * 
 * @param packet: the packet himself.
 * @param length: the length of the packet.
 */
void sctp_analayze(const u_char *packet, uint length);

#endif //SCTP_H