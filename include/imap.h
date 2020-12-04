#ifndef IMAP_H
#define IMAP_H
#include "application_layout.h"

/**
 * @brief Print the content of a IMAP packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void imap_analyze(const u_char *packet, uint length);

#endif //IMAP_H