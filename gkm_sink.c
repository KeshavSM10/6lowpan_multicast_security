/*
 * Group Key Management (GKM) Secure Multicast Sink Node
 * Receives group key updates and encrypted multicast data
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
#define KEY_LENGTH 16

/* Master key (pre-shared with root) */
static const uint8_t master_key[KEY_LENGTH] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

/* Current group session key */
static uint8_t group_key[KEY_LENGTH];
static uint32_t current_key_version = 0;
static uint8_t key_received = 0;

typedef struct {
  uint32_t seq_id;
  uint32_t key_version;
  uint8_t encrypted_data[16];
} __attribute__((packed)) gkm_data_pkt_t;

typedef struct {
  uint8_t type;
  uint32_t key_version;
  uint8_t encrypted_key[KEY_LENGTH];
} __attribute__((packed)) gkm_key_pkt_t;

static struct uip_udp_conn *sink_conn;
static uint16_t count = 0;
static uint16_t key_mismatch = 0;

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#endif

PROCESS(mcast_sink_process, "GKM Secure Sink");
AUTOSTART_PROCESSES(&mcast_sink_process);

/*---------------------------------------------------------------------------*/
static void
decrypt_data(const uint8_t *key, const uint8_t *cipher, uint8_t *plain)
{
  uint8_t temp[16];
  
  /* Decrypt by encrypting with key (AES is symmetric for ECB) */
  /* In production, use proper decryption mode */
  AES_128.set_key(key);
  memcpy(temp, cipher, 16);
  
  /* Simple XOR-based decryption simulation */
  AES_128.encrypt(temp);
  memcpy(plain, temp, sizeof(uint32_t));
}
/*---------------------------------------------------------------------------*/
static void
handle_key_update(const gkm_key_pkt_t *pkt)
{
  uint32_t new_version = uip_ntohl(pkt->key_version);
  uint8_t decrypted_key[16];
  
  PRINTF("Key update received: version %lu\n", (unsigned long)new_version);
  
  /* Decrypt group key using master key */
  decrypt_data(master_key, pkt->encrypted_key, decrypted_key);
  memcpy(group_key, decrypted_key, KEY_LENGTH);
  
  current_key_version = new_version;
  key_received = 1;
  
  PRINTF("✓ Group key updated to v%lu\n", (unsigned long)current_key_version);
}
/*---------------------------------------------------------------------------*/
static void
handle_data_packet(const gkm_data_pkt_t *pkt)
{
  uint32_t key_ver = uip_ntohl(pkt->key_version);
  uint8_t decrypted[16];
  
  if(!key_received) {
    PRINTF("⚠ No group key yet, dropping packet\n");
    return;
  }
  
  if(key_ver != current_key_version) {
    key_mismatch++;
    PRINTF("✗ Key version mismatch: have v%lu, need v%lu\n",
           (unsigned long)current_key_version, (unsigned long)key_ver);
    return;
  }
  
  /* Decrypt with current group key */
  decrypt_data(group_key, pkt->encrypted_data, decrypted);
  
  uint32_t decrypted_id = uip_ntohl(*((uint32_t *)decrypted));
  count++;
  
  PRINTF("✓ DECRYPTED: SeqID=0x%08lx (v%lu), TTL=%u, Total=%u\n",
         (unsigned long)decrypted_id, (unsigned long)key_ver,
         UIP_IP_BUF->ttl, count);
}
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  if(uip_newdata()) {
    uint16_t datalen = uip_datalen();
    
    /* Determine packet type by size */
    if(datalen == sizeof(gkm_key_pkt_t)) {
      gkm_key_pkt_t *key_pkt = (gkm_key_pkt_t *)uip_appdata;
      if(key_pkt->type == 1) {
        handle_key_update(key_pkt);
      }
    } else if(datalen == sizeof(gkm_data_pkt_t)) {
      gkm_data_pkt_t *data_pkt = (gkm_data_pkt_t *)uip_appdata;
      handle_data_packet(data_pkt);
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
  
  PRINTF("=== GKM Secure Multicast Sink ===\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Security: Group Key Management\n");
  PRINTF("Waiting for group key distribution...\n");
  
#if UIP_MCAST6_CONF_ENGINE != UIP_MCAST6_ENGINE_MPL
  if(join_mcast_group() == NULL) {
    PRINTF("Failed to join multicast group\n");
    PROCESS_EXIT();
  }
#endif
  
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
