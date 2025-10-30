/*
 * AES-CCM Secure Multicast Sink Node
 * Receives and decrypts AES-CCM encrypted multicast messages
 * Verifies message integrity using MIC
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "lib/aes-128.h"

#include <stdio.h>
#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#define MCAST_SINK_UDP_PORT 3001
#define AES_128_KEY_LENGTH 16
#define MIC_LENGTH 8
#define NONCE_LENGTH 13

/* Shared symmetric key (same as root) */
static const uint8_t aes_key[AES_128_KEY_LENGTH] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

typedef struct {
  uint32_t seq_id;
  uint32_t counter;
  uint8_t ciphertext[sizeof(uint32_t)];
  uint8_t mic[MIC_LENGTH];
} __attribute__((packed)) secure_packet_t;

static struct uip_udp_conn *sink_conn;
static uint16_t count;
static uint16_t auth_failures = 0;

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#endif

PROCESS(mcast_sink_process, "AES-CCM Secure Sink");
AUTOSTART_PROCESSES(&mcast_sink_process);

/*---------------------------------------------------------------------------*/
static void
generate_nonce(uint8_t *nonce, uint32_t counter)
{
  memset(nonce, 0, NONCE_LENGTH);
  nonce[0] = (counter >> 24) & 0xFF;
  nonce[1] = (counter >> 16) & 0xFF;
  nonce[2] = (counter >> 8) & 0xFF;
  nonce[3] = counter & 0xFF;
  // rest zero or constant
}

/*---------------------------------------------------------------------------*/
static int
decrypt_and_verify(const uint8_t *ciphertext, uint16_t len,
                   uint8_t *plaintext, const uint8_t *mic, uint32_t counter)
{
  uint8_t nonce[NONCE_LENGTH];
  uint8_t temp[16];
  uint8_t computed_mic[MIC_LENGTH];
  
  generate_nonce(nonce, counter);
  
  AES_128.set_key(aes_key);
  
  /* Decrypt */
  memset(temp, 0, 16);
  memcpy(temp, nonce, NONCE_LENGTH);
  AES_128.encrypt(temp);
  
  for(int i = 0; i < len; i++) {
    plaintext[i] = ciphertext[i] ^ temp[i];
  }
  
  /* Verify MIC */
  memset(temp, 0, 16);
  memcpy(temp, plaintext, len);
  AES_128.encrypt(temp);
  memcpy(computed_mic, temp, MIC_LENGTH);
  
  if(memcmp(mic, computed_mic, MIC_LENGTH) != 0) {
    return 0;
  }
  
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  if(uip_newdata()) {
    secure_packet_t *pkt = (secure_packet_t *)uip_appdata;
    uint8_t plaintext[sizeof(uint32_t)];
    uint32_t seq_id, counter;
    
    seq_id = uip_ntohl(pkt->seq_id);
    counter = uip_ntohl(pkt->counter);
    
    if(decrypt_and_verify(pkt->ciphertext, sizeof(uint32_t),
                         plaintext, pkt->mic, counter)) {
      uint32_t decrypted_id = uip_ntohl(*((uint32_t *)plaintext));
      count++;
      PRINTF("✓ AUTH OK: SeqID=0x%08lx (Orig=0x%08lx), TTL=%u, Total=%u\n",
       (unsigned long)decrypted_id,
       (unsigned long)seq_id,
       UIP_IP_BUF->ttl,
       count);

    } else {
      auth_failures++;
      PRINTF("✗ AUTH FAIL: Total failures=%u\n", auth_failures);
    }
  }
}
/*---------------------------------------------------------------------------*/
#if UIP_MCAST6_CONF_ENGINE != UIP_MCAST6_ENGINE_MPL
static uip_ds6_maddr_t *
join_mcast_group(void)
{
  uip_ipaddr_t addr;
  uip_ds6_maddr_t *rv;
  const uip_ipaddr_t *default_prefix = uip_ds6_default_prefix();
  
  uip_ip6addr_copy(&addr, default_prefix);
  uip_ds6_set_addr_iid(&addr, &uip_lladdr);
  uip_ds6_addr_add(&addr, 0, ADDR_AUTOCONF);
  
  uip_ip6addr(&addr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
  rv = uip_ds6_maddr_add(&addr);
  
  if(rv) {
    PRINTF("Joined multicast group ");
    PRINT6ADDR(&uip_ds6_maddr_lookup(&addr)->ipaddr);
    PRINTF("\n");
  }
  return rv;
}
#endif
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_sink_process, ev, data)
{
  PROCESS_BEGIN();
  
  PRINTF("=== AES-CCM Secure Multicast Sink ===\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Security: AES-128-CCM with %d-byte MIC\n", MIC_LENGTH);
  
#if UIP_MCAST6_CONF_ENGINE != UIP_MCAST6_ENGINE_MPL
  if(join_mcast_group() == NULL) {
    PRINTF("Failed to join multicast group\n");
    PROCESS_EXIT();
  }
#endif
  
  count = 0;
  
  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  if(sink_conn == NULL) {
    PRINTF("No UDP connection available!\n");
    PROCESS_EXIT();
  }
  
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));
  
  PRINTF("Listening on port %u\n", MCAST_SINK_UDP_PORT);
  
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
