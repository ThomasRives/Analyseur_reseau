#ifndef SMTP_H
#define SMTP_H
#include "application_layout.h"

#define PORT_SMTP 25

/**
 * @brief Print the content of an SMTP packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void smtp_analyze(const u_char *packet, uint length);

#endif //SMTP_H