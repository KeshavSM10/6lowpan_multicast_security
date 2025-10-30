/*
 * GKM Secure Multicast Intermediate Node
 * Forwards encrypted packets and key distribution messages
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <stdio.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#endif

PROCESS(mcast_intermediate_process, "GKM Secure Intermediate");
AUTOSTART_PROCESSES(&mcast_intermediate_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_intermediate_process, ev, data)
{
  PROCESS_BEGIN();
  
  PRINTF("=== GKM Secure Multicast Intermediate ===\n");
  PRINTF("Mode: Transparent forwarding\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Forwarding encrypted data and key updates\n");
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
