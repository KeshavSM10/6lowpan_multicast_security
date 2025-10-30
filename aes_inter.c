/*
 * AES-CCM Secure Multicast Intermediate Node
 * Forwards encrypted multicast packets without decryption
 * Maintains network routing while preserving end-to-end encryption
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

PROCESS(mcast_intermediate_process, "AES-CCM Secure Intermediate");
AUTOSTART_PROCESSES(&mcast_intermediate_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_intermediate_process, ev, data)
{
  PROCESS_BEGIN();
  
  PRINTF("=== AES-CCM Secure Multicast Intermediate ===\n");
  PRINTF("Mode: Transparent encrypted packet forwarding\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Note: Packets forwarded without decryption (end-to-end security)\n");
  
  /* Intermediate node just forwards encrypted packets
   * No decryption needed - maintains end-to-end security */
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
