/*
 * Group Key Management (GKM) Secure Multicast Root Node
 * Implements centralized key distribution and management
 * 
 * Security Features:
 * - Session key distribution to group members
 * - Periodic key refresh
 * - Encrypted group communication
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "lib/aes-128.h"
#include "lib/random.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"
#include "net/routing/routing.h"

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001
#define KEY_MGMT_PORT 3002
#define SEND_INTERVAL CLOCK_SECOND
#define ITERATIONS 100
#define START_DELAY 60
#define KEY_REFRESH_INTERVAL 20

#define KEY_LENGTH 16
#define MAX_GROUP_MEMBERS 10

/* Master key for key distribution (pre-shared with all nodes) */
static const uint8_t master_key[KEY_LENGTH] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

/* Current group session key */
static uint8_t group_key[KEY_LENGTH];
static uint32_t group_key_version = 1;

/* Group member list */
typedef struct {
  uip_ipaddr_t addr;
  uint8_t active;
} member_t;

static member_t members[MAX_GROUP_MEMBERS] __attribute__((unused));
static uint8_t member_count __attribute__((unused)) = 0;

/* Packet structures */
typedef struct {
  uint32_t seq_id;
  uint32_t key_version;
  uint8_t encrypted_data[16];
} __attribute__((packed)) gkm_data_pkt_t;

typedef struct {
  uint8_t type;  /* 1=KEY_UPDATE */
  uint32_t key_version;
  uint8_t encrypted_key[KEY_LENGTH];
} __attribute__((packed)) gkm_key_pkt_t;

static struct uip_udp_conn *mcast_conn;
static struct uip_udp_conn *keymgmt_conn;
static uint32_t seq_id;

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#endif

PROCESS(rpl_root_process, "GKM Secure Root");
PROCESS(key_mgmt_process, "GKM Key Manager");
AUTOSTART_PROCESSES(&rpl_root_process, &key_mgmt_process);

/*---------------------------------------------------------------------------*/
static void
generate_group_key(void)
{
  for(int i = 0; i < KEY_LENGTH; i++) {
    group_key[i] = (random_rand() & 0xFF);
  }
  PRINTF("Generated new group key (v%lu)\n", (unsigned long)group_key_version);
}
/*---------------------------------------------------------------------------*/
static void
encrypt_data(const uint8_t *key, const uint8_t *plain, uint8_t *cipher)
{
  uint8_t temp[16];
  AES_128.set_key(key);
  memset(temp, 0, 16);
  memcpy(temp, plain, sizeof(uint32_t));
  AES_128.encrypt(temp);
  memcpy(cipher, temp, 16);
}
/*---------------------------------------------------------------------------*/
static void
distribute_group_key(void)
{
  gkm_key_pkt_t key_pkt;
  
  key_pkt.type = 1;
  key_pkt.key_version = uip_htonl(group_key_version);
  
  /* Encrypt group key with master key */
  encrypt_data(master_key, group_key, key_pkt.encrypted_key);
  
  PRINTF("Distributing group key v%lu\n", (unsigned long)group_key_version);
  
  /* Broadcast key to all members */
  uip_udp_packet_send(mcast_conn, &key_pkt, sizeof(key_pkt));
}
/*---------------------------------------------------------------------------*/
static void
multicast_send(void)
{
  gkm_data_pkt_t pkt;
  uint32_t id;
  uint8_t plaintext[sizeof(uint32_t)];
  
  /* Refresh key periodically */
  if(seq_id > 0 && (seq_id % KEY_REFRESH_INTERVAL) == 0) {
    group_key_version++;
    generate_group_key();
    distribute_group_key();
  }
  
  id = uip_htonl(seq_id);
  memcpy(plaintext, &id, sizeof(id));
  
  pkt.seq_id = id;
  pkt.key_version = uip_htonl(group_key_version);
  
  /* Encrypt with current group key */
  encrypt_data(group_key, plaintext, pkt.encrypted_data);
  
  PRINTF("Send SeqID=0x%08"PRIx32" KeyVer=%lu [ENCRYPTED]\n",
         seq_id, (unsigned long)group_key_version);
  
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
  keymgmt_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(keymgmt_conn, UIP_HTONS(KEY_MGMT_PORT));
}
/*---------------------------------------------------------------------------*/
static void
key_mgmt_handler(void)
{
  if(uip_newdata()) {
    PRINTF("Key management packet received\n");
    /* Handle join requests, etc. */
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(key_mgmt_process, ev, data)
{
  PROCESS_BEGIN();
  
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      key_mgmt_handler();
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
  static struct etimer et;
  
  PROCESS_BEGIN();
  
  PRINTF("=== GKM Secure Multicast Root ===\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Security: Group Key Management with key refresh\n");
  
  /* Initialize first group key */
  random_init(123);
  generate_group_key();
  
  NETSTACK_ROUTING.root_start();
  prepare_mcast();
  
  etimer_set(&et, START_DELAY * CLOCK_SECOND);
  
  /* Distribute initial key */
  etimer_set(&et, (START_DELAY - 5) * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  distribute_group_key();
  
  etimer_set(&et, 5 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      if(seq_id == ITERATIONS) {
        PRINTF("Transmission complete\n");
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
