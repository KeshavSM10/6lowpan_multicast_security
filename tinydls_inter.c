/*
 * TinyDTLS Secure Multicast Intermediate Node
 * Forwards DTLS-encrypted packets and handshake messages
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

PROCESS(mcast_intermediate_process, "TinyDTLS Secure Intermediate");
AUTOSTART_PROCESSES(&mcast_intermediate_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_intermediate_process, ev, data)
{
  PROCESS_BEGIN();
  
  PRINTF("=== TinyDTLS Secure Multicast Intermediate ===\n");
  PRINTF("Mode: Transparent forwarding\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Forwarding DTLS handshake and encrypted data\n");
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
