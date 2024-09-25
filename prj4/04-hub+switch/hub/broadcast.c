#include "base.h"
#include <stdio.h>

extern ustack_t *instance;

// the function for sending packet, defined in device_internal.c
extern void iface_send_packet(iface_info_t *iface, const char *packet, int len);

// the memory of ``packet'' will be free'd in handle_packet().
void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet 
	iface_info_t *iface_entry;

	list_for_each_entry(iface_entry, &instance -> iface_list, list) 
	{
		if (iface_entry -> fd != iface -> fd)
		{
			iface_send_packet(iface_entry, packet, len);
		}
	}
}
