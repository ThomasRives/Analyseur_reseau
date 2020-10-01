#ifndef H_INTERFACES
#define H_INTERFACES
#include <pcap.h>
#include <string.h>
#include "utilities.h"

/**
 * @brief Search the interface chosen by the user.
 *
 * @param interface_name: the name of the interface that the user is looking for
 * @return a pointer to a structure that represent an interface.
 */
pcap_if_t *get_selected_interface(const char *interface_name);

/**
 * @brief Print all the availables interfaces on your device.
 */
void print_all_interfaces(void);

#endif
