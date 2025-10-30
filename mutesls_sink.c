/*
 * µTESLA Secure Multicast Sink Node
 * Receives authenticated broadcast messages and verifies MACs
 * Uses disclosed keys to verify message authenticity
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

/* µTESLA Parameters */
#define KEY_CHAIN_LENGTH 100
#define KEY_LENGTH 16
#define MAC_LENGTH 8
#define MAX_BUFFERED_PACKETS 10

/* µTESLA packet structure */
typedef struct {
  uint32_t seq_id;
  uint32_t timestamp;
  uint8_t mac[MAC_LENGTH];
  uint8_t data[sizeof(uint32_t)];
} __attribute__((packed)) utesla_packet_t;

/* Key disclosure packet */
typedef struct {
  uint32_t key_interval;
  uint8_t key[KEY_LENGTH];
} __attribute__((packed)) key_disclosure_t;

/* Buffered packet waiting for key disclosure */
typedef struct {
  utesla_packet_t pkt;
  uint8_t valid;
} buffered_packet_t;

static struct uip_udp_conn *sink_conn;
static uint16_t count = 0;
static uint16_t auth_failures = 0;

/* Commitment key (K0) - would be securely distributed */
static uint8_t commitment_key[KEY_LENGTH] = {
  0x6e, 0x7c, 0x8a, 0x42, 0x19, 0xf5, 0x31, 0x0d,
  0x9e, 0x2a, 0x74, 0x61, 0xc3, 0x55, 0xb8, 0x0f
};

/* Disclosed keys storage */
static uint8_t disclosed_keys[KEY_CHAIN_LENGTH][KEY_LENGTH];
static uint8_t key_disclosed[KEY_CHAIN_LENGTH] = {0};

/* Buffer for packets waiting for key disclosure */
static buffered_packet_t packet_buffer[MAX_BUFFERED_PACKETS];

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#endif

PROCESS(mcast_sink_process, "µTESLA Secure Sink");
AUTOSTART_PROCESSES(&mcast_sink_process);

/*---------------------------------------------------------------------------*/
static void
hash_function(const uint8_t *input, uint16_t len, uint8_t *output)
{
  uint8_t temp[KEY_LENGTH];
  int i;
  
  AES_128.set_key(input);
  memset(temp, 0, KEY_LENGTH);
  AES_128.encrypt(temp);
  
  for(i = 0; i < KEY_LENGTH && i < len; i++) {
    output[i] = temp[i] ^ input[i];
  }
  for(; i < KEY_LENGTH; i++) {
    output[i] = temp[i];
  }
}
/*---------------------------------------------------------------------------*/
static int
verify_key_authenticity(uint32_t interval, const uint8_t *key)
{
  uint8_t hash[KEY_LENGTH];
  uint8_t current[KEY_LENGTH];
  uint32_t i;
  
  if(interval >= KEY_CHAIN_LENGTH) return 0;
  
  /* Hash the key forward to commitment */
  memcpy(current, key, KEY_LENGTH);
  
  for(i = interval; i > 0; i--) {
    hash_function(current, KEY_LENGTH, hash);
    memcpy(current, hash, KEY_LENGTH);
  }
  
  /* Compare with commitment (K0) */
  if(memcmp(current, commitment_key, KEY_LENGTH) == 0) {
    PRINTF("✓ Key for interval %lu verified authentic\n",
           (unsigned long)interval);
    return 1;
  }
  
  PRINTF("✗ Key verification FAILED for interval %lu\n",
         (unsigned long)interval);
  return 0;
}
/*---------------------------------------------------------------------------*/
static void
compute_mac(const uint8_t *key, const uint8_t *data, uint16_t data_len,
            uint8_t *mac)
{
  uint8_t temp[KEY_LENGTH];
  
  AES_128.set_key(key);
  memset(temp, 0, KEY_LENGTH);
  memcpy(temp, data, data_len < KEY_LENGTH ? data_len : KEY_LENGTH);
  AES_128.encrypt(temp);
  memcpy(mac, temp, MAC_LENGTH);
}
/*---------------------------------------------------------------------------*/
static int
verify_packet(const utesla_packet_t *pkt, uint32_t interval)
{
  uint8_t computed_mac[MAC_LENGTH];
  
  if(interval >= KEY_CHAIN_LENGTH || !key_disclosed[interval]) {
    return -1; /* Key not yet disclosed */
  }
  
  /* Compute MAC with disclosed key */
  compute_mac(disclosed_keys[interval], (const uint8_t *)pkt,
              sizeof(utesla_packet_t) - MAC_LENGTH, computed_mac);
  
  /* Verify MAC */
  if(memcmp(pkt->mac, computed_mac, MAC_LENGTH) == 0) {
    return 1; /* Authentic */
  }
  
  return 0; /* Authentication failed */
}
/*---------------------------------------------------------------------------*/
static void
process_buffered_packets(void)
{
  int i;
  
  for(i = 0; i < MAX_BUFFERED_PACKETS; i++) {
    if(!packet_buffer[i].valid) continue;
    
    uint32_t interval = uip_ntohl(packet_buffer[i].pkt.timestamp);
    int result = verify_packet(&packet_buffer[i].pkt, interval);
    
    if(result == 1) {
      /* Authenticated */
      uint32_t seq_id = uip_ntohl(packet_buffer[i].pkt.seq_id);
      count++;
      PRINTF("✓ BUFFERED PKT AUTHENTICATED: SeqID=0x%08lx, Total=%u\n",
             (unsigned long)seq_id, count);
      packet_buffer[i].valid = 0;
    } else if(result == 0) {
      /* Failed authentication */
      auth_failures++;
      PRINTF("✗ BUFFERED PKT AUTH FAILED\n");
      packet_buffer[i].valid = 0;
    }
    /* If result == -1, keep waiting for key */
  }
}
/*---------------------------------------------------------------------------*/
static void
handle_key_disclosure(const key_disclosure_t *key_pkt)
{
  uint32_t interval = uip_ntohl(key_pkt->key_interval);
  
  PRINTF("Received key disclosure for interval %lu\n",
         (unsigned long)interval);
  
  if(interval >= KEY_CHAIN_LENGTH) {
    PRINTF("Invalid interval\n");
    return;
  }
  
  /* Verify key authenticity */
  if(verify_key_authenticity(interval, key_pkt->key)) {
    memcpy(disclosed_keys[interval], key_pkt->key, KEY_LENGTH);
    key_disclosed[interval] = 1;
    
    /* Process any buffered packets waiting for this key */
    process_buffered_packets();
  }
}
/*---------------------------------------------------------------------------*/
static void
buffer_packet(const utesla_packet_t *pkt)
{
  int i;
  
  /* Find empty slot */
  for(i = 0; i < MAX_BUFFERED_PACKETS; i++) {
    if(!packet_buffer[i].valid) {
      memcpy(&packet_buffer[i].pkt, pkt, sizeof(utesla_packet_t));
      packet_buffer[i].valid = 1;
      PRINTF("Packet buffered (waiting for key disclosure)\n");
      return;
    }
  }
  
  PRINTF("Buffer full! Packet dropped\n");
}
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  if(uip_newdata()) {
    uint16_t datalen = uip_datalen();
    
    /* Check if it's a key disclosure packet */
    if(datalen == sizeof(key_disclosure_t)) {
      key_disclosure_t *key_pkt = (key_disclosure_t *)uip_appdata;
      handle_key_disclosure(key_pkt);
      return;
    }
    
    /* Otherwise, it's a data packet */
    if(datalen == sizeof(utesla_packet_t)) {
      utesla_packet_t *pkt = (utesla_packet_t *)uip_appdata;
      uint32_t interval = uip_ntohl(pkt->timestamp);
      uint32_t seq_id = uip_ntohl(pkt->seq_id);
      
      PRINTF("Received packet: SeqID=0x%08lx, Interval=%lu\n",
             (unsigned long)seq_id, (unsigned long)interval);
      
      int result = verify_packet(pkt, interval);
      
      if(result == 1) {
        count++;
        PRINTF("✓ AUTHENTICATED: SeqID=0x%08lx, Total=%u\n",
               (unsigned long)seq_id, count);
      } else if(result == -1) {
        PRINTF("Key not yet disclosed, buffering packet\n");
        buffer_packet(pkt);
      } else {
        auth_failures++;
        PRINTF("✗ AUTH FAILED: Total failures=%u\n", auth_failures);
      }
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
  
  PRINTF("=== µTESLA Secure Multicast Sink ===\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Security: Broadcast authentication with key disclosure\n");
  
  /* Initialize commitment key (in production, this would be securely distributed) */
  PRINTF("Commitment key (K0): ");
  for(int i = 0; i < 8; i++) {
    PRINTF("%02x", commitment_key[i]);
  }
  PRINTF("...\n");
  
#if UIP_MCAST6_CONF_ENGINE != UIP_MCAST6_ENGINE_MPL
  if(join_mcast_group() == NULL) {
    PRINTF("Failed to join multicast group\n");
    PROCESS_EXIT();
  }
#endif
  
  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  if(sink_conn == NULL) {
    PRINTF("No UDP connection available, exiting!\n");
    PROCESS_EXIT();
  }
  
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));
  
  PRINTF("Listening: ");
  PRINT6ADDR(&sink_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
         UIP_HTONS(sink_conn->lport), UIP_HTONS(sink_conn->rport));
  
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
