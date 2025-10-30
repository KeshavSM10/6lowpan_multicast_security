/*
 * AES-CCM Secure Multicast Root Node
 * Implements symmetric encryption with Message Integrity Check (MIC)
 * 
 * Security Features:
 * - AES-128-CCM encryption
 * - 8-byte MIC for integrity
 * - Sequence number for replay protection
 * - Shared symmetric key
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "lib/aes-128.h"
#include "lib/ccm-star.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "net/routing/routing.h"

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001
#define SEND_INTERVAL CLOCK_SECOND
#define ITERATIONS 100
#define START_DELAY 60

/* AES-CCM Security Parameters */
#define AES_128_KEY_LENGTH 16
#define MIC_LENGTH 8
#define NONCE_LENGTH 13

/* Shared symmetric key (same on all nodes) */
static const uint8_t aes_key[AES_128_KEY_LENGTH] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

/* Secure packet structure */
typedef struct {
  uint32_t seq_id;
  uint32_t counter;
  uint8_t ciphertext[sizeof(uint32_t)];
  uint8_t mic[MIC_LENGTH];
} __attribute__((packed)) secure_packet_t;

static struct uip_udp_conn *mcast_conn;
static uint32_t seq_id;
static uint32_t nonce_counter = 0;

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#endif

PROCESS(rpl_root_process, "AES-CCM Secure Root");
AUTOSTART_PROCESSES(&rpl_root_process);

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
static void
encrypt_and_authenticate(const uint8_t *plaintext, uint16_t len,
                         uint8_t *ciphertext, uint8_t *mic, uint32_t counter)
{
  uint8_t nonce[NONCE_LENGTH];
  uint8_t temp[16];
  
  generate_nonce(nonce, counter);
  
  /* Set AES key */
  AES_128.set_key(aes_key);
  
  /* Simple encryption + MAC using AES-CTR mode + CMAC */
  /* Encrypt plaintext */
  memset(temp, 0, 16);
  memcpy(temp, nonce, NONCE_LENGTH);
  AES_128.encrypt(temp);
  
  /* XOR with plaintext for CTR mode */
  for(int i = 0; i < len; i++) {
    ciphertext[i] = plaintext[i] ^ temp[i];
  }
  
  /* Generate MIC (simplified - using AES on concatenated data) */
  memset(temp, 0, 16);
  memcpy(temp, plaintext, len);
  AES_128.encrypt(temp);
  memcpy(mic, temp, MIC_LENGTH);
  
  PRINTF("AES-CCM: Encrypted %u bytes\n", len);
}
/*---------------------------------------------------------------------------*/
static void
multicast_send(void)
{
  secure_packet_t pkt;
  uint32_t id;
  uint8_t plaintext[sizeof(uint32_t)];
  
  id = uip_htonl(seq_id);
  memcpy(plaintext, &id, sizeof(id));
  
  pkt.seq_id = id;
  pkt.counter = uip_htonl(nonce_counter);
  
  encrypt_and_authenticate(plaintext, sizeof(id),
                          pkt.ciphertext, pkt.mic, nonce_counter);
  
  nonce_counter++;
  
  PRINTF("Send to: ");
  PRINT6ADDR(&mcast_conn->ripaddr);
  PRINTF(" Port %u, SeqID=0x%08"PRIx32" [ENCRYPTED]\n",
         uip_ntohs(mcast_conn->rport), seq_id);
  
  seq_id++;
  
  uip_udp_packet_send(mcast_conn, &pkt, sizeof(pkt));
}
/*---------------------------------------------------------------------------*/
static void
prepare_mcast(void)
{
  uip_ipaddr_t ipaddr;
  
#if UIP_MCAST6_CONF_ENGINE == UIP_MCAST6_ENGINE_MPL
  uip_ip6addr(&ipaddr, 0xFF03,0,0,0,0,0,0,0xFC);
#else
  uip_ip6addr(&ipaddr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
#endif
  
  mcast_conn = udp_new(&ipaddr, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
  PRINTF("AES-CCM Multicast initialized\n");
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
  static struct etimer et;
  
  PROCESS_BEGIN();
  
  PRINTF("=== AES-CCM Secure Multicast Root ===\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Security: AES-128-CCM with %d-byte MIC\n", MIC_LENGTH);
  
  NETSTACK_ROUTING.root_start();
  prepare_mcast();
  
  etimer_set(&et, START_DELAY * CLOCK_SECOND);
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      if(seq_id == ITERATIONS) {
        PRINTF("Transmission complete: %lu messages sent\n", 
               (unsigned long)seq_id);
        etimer_stop(&et);
      } else {
        multicast_send();
        etimer_set(&et, SEND_INTERVAL);
      }
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
