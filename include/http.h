#ifndef HTTP_H
#define HTTP_H
#include "application_layout.h"

#define PORT_HTTP 80

/**
 * @brief Print the content of a http packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void http_analyze(const u_char *packet, uint length);

#endif //HTTP_H