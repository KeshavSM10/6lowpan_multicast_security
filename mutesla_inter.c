/*
 * µTESLA Secure Multicast Intermediate Node
 * Forwards authenticated broadcast packets
 * No verification needed - receivers verify after key disclosure
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

PROCESS(mcast_intermediate_process, "µTESLA Secure Intermediate");
AUTOSTART_PROCESSES(&mcast_intermediate_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_intermediate_process, ev, data)
{
  PROCESS_BEGIN();
  
  PRINTF("=== µTESLA Secure Multicast Intermediate ===\n");
  PRINTF("Mode: Transparent authenticated packet forwarding\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Note: Authentication verified at receivers after key disclosure\n");
  
  /* Intermediate node forwards packets without verification
   * Receivers will verify authenticity when keys are disclosed */
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
