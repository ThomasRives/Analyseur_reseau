#ifndef POP_H
#define POP_H
#include "application_layout.h"

/**
 * @brief Print the content of a POP packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void pop_analyze(const u_char *packet, uint length);

#endif //POP_H