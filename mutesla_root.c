/*
 * µTESLA Secure Multicast Root Node
 * Implements lightweight broadcast authentication with delayed key disclosure
 * 
 * Security Features:
 * - Time-synchronized broadcast authentication
 * - Hash chain for key generation
 * - Delayed key disclosure (after time interval δ)
 * - MAC-based message authentication
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "lib/aes-128.h"
#include "sys/clock.h"

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

/* µTESLA Parameters */
#define KEY_CHAIN_LENGTH 100
#define KEY_LENGTH 16
#define MAC_LENGTH 8
#define KEY_DISCLOSURE_DELAY 2  /* Disclose key after 2 time intervals */

/* µTESLA packet structure */
typedef struct {
  uint32_t seq_id;
  uint32_t timestamp;  /* Time interval index */
  uint8_t mac[MAC_LENGTH];
  uint8_t data[sizeof(uint32_t)];
} __attribute__((packed)) utesla_packet_t;

/* Key disclosure packet */
typedef struct {
  uint32_t key_interval;  /* Which interval this key is for */
  uint8_t key[KEY_LENGTH];
} __attribute__((packed)) key_disclosure_t;

static struct uip_udp_conn *mcast_conn;
static uint32_t seq_id;
static uint32_t current_interval = 0;

/* Pre-computed hash chain (K0 <- K1 <- K2 <- ... <- Kn) */
static uint8_t key_chain[KEY_CHAIN_LENGTH][KEY_LENGTH];
static uint8_t chain_initialized = 0;

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#endif

PROCESS(rpl_root_process, "µTESLA Secure Root");
AUTOSTART_PROCESSES(&rpl_root_process);

/*---------------------------------------------------------------------------*/
/* Simple hash function (SHA-256 would be better in production) */
static void
hash_function(const uint8_t *input, uint16_t len, uint8_t *output)
{
  uint8_t temp[KEY_LENGTH];
  
  /* Use AES as hash (Davies-Meyer construction) */
  AES_128.set_key(input);
  memset(temp, 0, KEY_LENGTH);
  AES_128.encrypt(temp);
  
  /* XOR with input for Davies-Meyer */
  for(int i = 0; i < KEY_LENGTH && i < len; i++) {
    output[i] = temp[i] ^ input[i];
  }
  for(int i = 0; i < KEY_LENGTH; i++) {
    output[i] = temp[i];
  }
}
/*---------------------------------------------------------------------------*/
static void
initialize_key_chain(void)
{ 
  if(chain_initialized) return;
  
  PRINTF("Initializing µTESLA key chain...\n");
  
  /* Start with random seed (Kn) */
  memset(key_chain[KEY_CHAIN_LENGTH - 1], 0xAA, KEY_LENGTH);
  
  /* Generate chain backwards: Ki = H(Ki+1) */
  for(int i = KEY_CHAIN_LENGTH - 2; i >= 0; i--) {
    hash_function(key_chain[i + 1], KEY_LENGTH, key_chain[i]);
  }
  
  PRINTF("Key chain initialized: %d keys generated\n", KEY_CHAIN_LENGTH);
  
  /* K0 is the commitment - would be distributed securely to all nodes */
  PRINTF("Commitment (K0): ");
  for(int i = 0; i < 8; i++) {
    PRINTF("%02x", key_chain[0][i]);
  }
  PRINTF("...\n");
  
  chain_initialized = 1;
}
/*---------------------------------------------------------------------------*/
static void
compute_mac(const uint8_t *key, const uint8_t *data, uint16_t data_len,
            uint8_t *mac)
{
  uint8_t temp[KEY_LENGTH];
  
  /* Simple MAC: MAC = AES_key(data) */
  AES_128.set_key(key);
  
  /* Pad data to 16 bytes */
  memset(temp, 0, KEY_LENGTH);
  memcpy(temp, data, data_len < KEY_LENGTH ? data_len : KEY_LENGTH);
  
  AES_128.encrypt(temp);
  
  /* Take first MAC_LENGTH bytes */
  memcpy(mac, temp, MAC_LENGTH);
}
/*---------------------------------------------------------------------------*/
static void
multicast_send(void)
{
  utesla_packet_t pkt;
  uint32_t id;
  
  if(current_interval >= KEY_CHAIN_LENGTH) {
    PRINTF("Key chain exhausted!\n");
    return;
  }
  
  id = uip_htonl(seq_id);
  
  /* Prepare packet */
  pkt.seq_id = id;
  pkt.timestamp = uip_htonl(current_interval);
  memcpy(pkt.data, &id, sizeof(id));
  
  /* Compute MAC using current interval key */
  compute_mac(key_chain[current_interval], (uint8_t *)&pkt,
              sizeof(pkt) - MAC_LENGTH, pkt.mac);
  
  PRINTF("Send SeqID=0x%08"PRIx32" Interval=%lu MAC=",
         seq_id, (unsigned long)current_interval);
  for(int i = 0; i < 4; i++) {
    PRINTF("%02x", pkt.mac[i]);
  }
  PRINTF("...\n");
  
  /* Send authenticated packet */
  uip_udp_packet_send(mcast_conn, &pkt, sizeof(pkt));
  
  /* Disclose old key after delay */
  if(current_interval >= KEY_DISCLOSURE_DELAY) {
    key_disclosure_t key_pkt;
    uint32_t disclosure_interval = current_interval - KEY_DISCLOSURE_DELAY;
    
    key_pkt.key_interval = uip_htonl(disclosure_interval);
    memcpy(key_pkt.key, key_chain[disclosure_interval], KEY_LENGTH);
    
    PRINTF("  → Disclosing key for interval %lu\n",
           (unsigned long)disclosure_interval);
    
    /* Send key disclosure (could be separate UDP port in production) */
    uip_udp_packet_send(mcast_conn, &key_pkt, sizeof(key_pkt));
  }
  
  seq_id++;
  current_interval++;
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
  PRINTF("µTESLA Multicast initialized\n");
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
  static struct etimer et;
  
  PROCESS_BEGIN();
  
  PRINTF("=== µTESLA Secure Multicast Root ===\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Security: Broadcast authentication with delayed key disclosure\n");
  PRINTF("Key disclosure delay: %d intervals\n", KEY_DISCLOSURE_DELAY);
  
  initialize_key_chain();
  
  NETSTACK_ROUTING.root_start();
  prepare_mcast();
  
  etimer_set(&et, START_DELAY * CLOCK_SECOND);
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      if(seq_id >= ITERATIONS || current_interval >= KEY_CHAIN_LENGTH) {
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
