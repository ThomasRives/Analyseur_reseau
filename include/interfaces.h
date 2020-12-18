#ifndef INTERFACES_H
#define INTERFACES_H

#include <pcap.h>
#include <string.h>
#include "utilities.h"

/**
 * @brief Search the interface chosen by the user.
 *
 * If the interface provided is not found, the list of all the detected
 * interfaces will be printed out.
 *
 * @param interface_name: the name of the interface that the user is looking for
 */
void check_selected_interface(const char *interface_name);

/**
 * @brief Print all the availables interfaces on your device.
 */
void print_all_interfaces(void);

#endif //INTERFACES_H
