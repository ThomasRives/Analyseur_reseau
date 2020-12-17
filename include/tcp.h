#ifndef TCP_H
#define TCP_H
#include "transport_layout.h"

/**
 * @brief Analyze the TCP header of the packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void tcp_header_analyze(const u_char *packet, uint length);

/**
 * @brief Print the tcp flags.
 * 
 * @param flags: the flags in the packet.
 */
void print_tcp_flags(uint8_t flags);

/**
 * @brief Print TCP options.
 * 
 * @param read_header: the number of bytes already read.
 * @param off: the data offset.
 * @param tcp_options: a pointer to the beginning of the options.
 */
void print_tcp_options(uint8_t read_header, uint8_t off, uint8_t *tcp_options);

#endif //TCP_H