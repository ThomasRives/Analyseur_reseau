#ifndef TELNET_H
#define TELNET_H
#include <stdio.h>
#include <arpa/telnet.h>
#include <stdint.h>

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