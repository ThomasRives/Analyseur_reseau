#ifndef TELNET_H
#define TELNET_H
#include "application_layout.h"

#define PORT_TELNET 23

/**
 * @brief Print the content of an telnet packet.
 * 
 * @param packet: the packet himself.
 * @param length: the packet length.
 */
void telnet_analyze(const u_char *packet, uint length);

/**
 * @brief Print the given command as a telnet command.
 * 
 * @param command	the command that will be printed.
 */
void print_telnet_command(uint8_t command);

/**
 * @brief Print the given suboption as a telnet suboption.
 * 
 * @param subopt	the suboption that will be printed.
 */
void print_telnet_suboption(uint8_t subopt);

#endif //TELNET_H