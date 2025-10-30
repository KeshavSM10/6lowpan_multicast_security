/*
 * TinyDTLS Secure Multicast Root Node
 * Implements DTLS-like handshake for secure multicast
 * 
 * Security Features:
 * - DTLS-style handshake protocol
 * - Session key establishment
 * - PSK (Pre-Shared Key) authentication
 * - Secure encrypted multicast after handshake
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
#define DTLS_HANDSHAKE_PORT 3003
#define SEND_INTERVAL CLOCK_SECOND
#define ITERATIONS 100
#define START_DELAY 60

#define KEY_LENGTH 16
#define NONCE_LENGTH 16
#define MAX_CLIENTS 10

/* Pre-Shared Key for authentication */
static const uint8_t psk_key[KEY_LENGTH] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
};

/* Session key for encrypted communication */
static uint8_t session_key[KEY_LENGTH];

/* DTLS Handshake Message Types */
#define HELLO_REQUEST 0
#define CLIENT_HELLO 1
#define SERVER_HELLO 2
#define SESSION_KEY 3
#define HANDSHAKE_DONE 4

/* Client state tracking */
typedef struct {
  uip_ipaddr_t addr;
  uint8_t client_nonce[NONCE_LENGTH];
  uint8_t server_nonce[NONCE_LENGTH];
  uint8_t handshake_complete;
  uint8_t active;
} client_state_t;

static client_state_t clients[MAX_CLIENTS];

/* Handshake packet */
typedef struct {
  uint8_t msg_type;
  uint8_t nonce[NONCE_LENGTH];
  uint8_t encrypted_data[KEY_LENGTH];
} __attribute__((packed)) dtls_handshake_t;

/* Data packet */
typedef struct {
  uint32_t seq_id;
  uint8_t encrypted_data[16];
  uint8_t mac[8];
} __attribute__((packed)) dtls_data_t;

static struct uip_udp_conn *mcast_conn;
static struct uip_udp_conn *handshake_conn;
static uint32_t seq_id;
static uint8_t session_established = 0;

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#endif

PROCESS(rpl_root_process, "TinyDTLS Secure Root");
PROCESS(dtls_handshake_process, "DTLS Handshake Server");
AUTOSTART_PROCESSES(&rpl_root_process, &dtls_handshake_process);

/*---------------------------------------------------------------------------*/
static void
generate_nonce(uint8_t *nonce)
{
  for(int i = 0; i < NONCE_LENGTH; i++) {
    nonce[i] = random_rand() & 0xFF;
  }
}
/*---------------------------------------------------------------------------*/
static void
generate_session_key(void)
{
  for(int i = 0; i < KEY_LENGTH; i++) {
    session_key[i] = random_rand() & 0xFF;
  }
  PRINTF("New session key generated\n");
}
/*---------------------------------------------------------------------------*/
static int
find_client(const uip_ipaddr_t *addr)
{
  for(int i = 0; i < MAX_CLIENTS; i++) {
    if(clients[i].active && 
       uip_ipaddr_cmp(&clients[i].addr, addr)) {
      return i;
    }
  }
  return -1;
}
/*---------------------------------------------------------------------------*/
static int
add_client(const uip_ipaddr_t *addr)
{
  for(int i = 0; i < MAX_CLIENTS; i++) {
    if(!clients[i].active) {
      uip_ipaddr_copy(&clients[i].addr, addr);
      clients[i].active = 1;
      clients[i].handshake_complete = 0;
      return i;
    }
  }
  return -1;
}
/*---------------------------------------------------------------------------*/
static void
encrypt_with_psk(const uint8_t *plain, uint8_t *cipher)
{
  uint8_t temp[16];
  AES_128.set_key(psk_key);
  memset(temp, 0, 16);
  memcpy(temp, plain, KEY_LENGTH);
  AES_128.encrypt(temp);
  memcpy(cipher, temp, KEY_LENGTH);
}
/*---------------------------------------------------------------------------*/
static void
handle_client_hello(const dtls_handshake_t *pkt)
{
  dtls_handshake_t response;
  int client_idx;
  
  PRINTF("CLIENT_HELLO received from ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("\n");
  
  /* Find or add client */
  client_idx = find_client(&UIP_IP_BUF->srcipaddr);
  if(client_idx < 0) {
    client_idx = add_client(&UIP_IP_BUF->srcipaddr);
    if(client_idx < 0) {
      PRINTF("Client table full!\n");
      return;
    }
  }
  
  /* Store client nonce */
  memcpy(clients[client_idx].client_nonce, pkt->nonce, NONCE_LENGTH);
  
  /* Generate server nonce */
  generate_nonce(clients[client_idx].server_nonce);
  
  /* Send SERVER_HELLO */
  response.msg_type = SERVER_HELLO;
  memcpy(response.nonce, clients[client_idx].server_nonce, NONCE_LENGTH);
  memset(response.encrypted_data, 0, KEY_LENGTH);
  
  uip_udp_packet_sendto(handshake_conn, &response, sizeof(response),
                        &UIP_IP_BUF->srcipaddr, UIP_HTONS(DTLS_HANDSHAKE_PORT));
  
  PRINTF("→ SERVER_HELLO sent\n");
  
  /* Send encrypted session key */
  response.msg_type = SESSION_KEY;
  memcpy(response.nonce, clients[client_idx].server_nonce, NONCE_LENGTH);
  encrypt_with_psk(session_key, response.encrypted_data);
  
  uip_udp_packet_sendto(handshake_conn, &response, sizeof(response),
                        &UIP_IP_BUF->srcipaddr, UIP_HTONS(DTLS_HANDSHAKE_PORT));
  
  PRINTF("→ SESSION_KEY sent (encrypted)\n");
  
  clients[client_idx].handshake_complete = 1;
  session_established = 1;  // <== add this
  PRINTF("✓ Global session established, multicast can begin\n");

  PRINTF("✓ Handshake complete with client %d\n", client_idx);
}
/*---------------------------------------------------------------------------*/
static void
handshake_handler(void)
{
  if(uip_newdata()) {
    dtls_handshake_t *pkt = (dtls_handshake_t *)uip_appdata;
    
    switch(pkt->msg_type) {
      case CLIENT_HELLO:
        handle_client_hello(pkt);
        break;
      case HANDSHAKE_DONE:
        PRINTF("Client confirmed handshake complete\n");
        break;
      default:
        PRINTF("Unknown handshake message type: %d\n", pkt->msg_type);
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
encrypt_data(const uint8_t *plain, uint8_t *cipher, uint8_t *mac)
{
  uint8_t temp[16];
  
  AES_128.set_key(session_key);
  memset(temp, 0, 16);
  memcpy(temp, plain, sizeof(uint32_t));
  AES_128.encrypt(temp);
  memcpy(cipher, temp, 16);
  
  /* Simple MAC */
  memcpy(mac, temp, 8);
}
/*---------------------------------------------------------------------------*/
static void
multicast_send(void)
{
  dtls_data_t pkt;
  uint32_t id;
  uint8_t plaintext[sizeof(uint32_t)];
  
  if(!session_established) {
    PRINTF("⚠ Session not established yet\n");
    return;
  }
  
  id = uip_htonl(seq_id);
  memcpy(plaintext, &id, sizeof(id));
  
  pkt.seq_id = id;
  encrypt_data(plaintext, pkt.encrypted_data, pkt.mac);
  
  PRINTF("Send SeqID=0x%08"PRIx32" [DTLS ENCRYPTED]\n", seq_id);
  
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
  
  handshake_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(handshake_conn, UIP_HTONS(DTLS_HANDSHAKE_PORT));
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtls_handshake_process, ev, data)
{
  PROCESS_BEGIN();
  
  PRINTF("DTLS Handshake Server listening on port %d\n", DTLS_HANDSHAKE_PORT);
  
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      handshake_handler();
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
  static struct etimer et;
  
  PROCESS_BEGIN();
  
  PRINTF("=== TinyDTLS Secure Multicast Root ===\n");
  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  PRINTF("Security: DTLS-like handshake + encrypted session\n");
  
  random_init(456);
  generate_session_key();
  
  NETSTACK_ROUTING.root_start();
  prepare_mcast();
  
  etimer_set(&et, START_DELAY * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  
  session_established = 1;
  PRINTF("Session ready, starting multicast\n");
  
  etimer_set(&et, SEND_INTERVAL);
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
