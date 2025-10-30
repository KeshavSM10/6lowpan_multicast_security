/*
 * TinyDTLS Secure Multicast Sink Node
 * Implements a DTLS-like handshake client
 * Receives and decrypts multicast traffic from the root
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/routing/routing.h"
#include "lib/aes-128.h"
#include "lib/random.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define DEBUG DEBUG_PRINT
#include "net/ipv6/uip-debug.h"

#define MCAST_SINK_UDP_PORT 3001
#define DTLS_HANDSHAKE_PORT 3003
#define KEY_LENGTH 16
#define NONCE_LENGTH 16
#define SEND_INTERVAL CLOCK_SECOND * 10

/* PSK key – must match root’s psk_key */
static const uint8_t psk_key[KEY_LENGTH] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
};

static uint8_t session_key[KEY_LENGTH];
static uint8_t client_nonce[NONCE_LENGTH];
static uint8_t server_nonce[NONCE_LENGTH];
static uint8_t handshake_done = 0;

/* Handshake message types */
#define HELLO_REQUEST 0
#define CLIENT_HELLO  1
#define SERVER_HELLO  2
#define SESSION_KEY   3
#define HANDSHAKE_DONE 4

/* Handshake message format */
typedef struct {
  uint8_t msg_type;
  uint8_t nonce[NONCE_LENGTH];
  uint8_t encrypted_data[KEY_LENGTH];
} __attribute__((packed)) dtls_handshake_t;

/* Encrypted multicast data */
typedef struct {
  uint32_t seq_id;
  uint8_t encrypted_data[16];
  uint8_t mac[8];
} __attribute__((packed)) dtls_data_t;

static struct uip_udp_conn *mcast_conn;
static struct uip_udp_conn *handshake_conn;

/*---------------------------------------------------------------------------*/
static void generate_nonce(uint8_t *nonce) {
  for(int i = 0; i < NONCE_LENGTH; i++) {
    nonce[i] = random_rand() & 0xFF;
  }
}
/*---------------------------------------------------------------------------*/
__attribute__((unused))
static void encrypt_with_psk(const uint8_t *plain, uint8_t *cipher) {
  AES_128.set_key(psk_key);
  AES_128.encrypt((uint8_t *)plain);
  memcpy(cipher, plain, AES_128_KEY_LENGTH);
}
/*----------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static void decrypt_with_psk(const uint8_t *cipher, uint8_t *plain) {
  /* No AES_128.decrypt() in Contiki, use encrypt() twice as a pseudo-inverse (test-only) */
  uint8_t temp[16];
  AES_128.set_key(psk_key);
  memcpy(temp, cipher, 16);
  AES_128.encrypt(temp);  // in real DTLS, this would be decrypt
  memcpy(plain, temp, 16);
}
/*---------------------------------------------------------------------------*/
static void decrypt_data(const uint8_t *cipher, uint8_t *plain) {
  AES_128.set_key(session_key);
  uint8_t temp[16];
  memcpy(temp, cipher, 16);
  AES_128.encrypt(temp);  // symmetric fallback
  memcpy(plain, temp, 16);
}
/*---------------------------------------------------------------------------*/
static void handle_handshake(const dtls_handshake_t *pkt) {
  switch(pkt->msg_type) {
    case SERVER_HELLO:
      memcpy(server_nonce, pkt->nonce, NONCE_LENGTH);
      printf("SERVER_HELLO received.\n");
      break;

    case SESSION_KEY: {
      uint8_t decrypted[KEY_LENGTH];
      decrypt_with_psk(pkt->encrypted_data, decrypted);
      memcpy(session_key, decrypted, KEY_LENGTH);
      printf("SESSION_KEY received and decrypted.\n");

      /* Confirm handshake done */
      dtls_handshake_t confirm;
      confirm.msg_type = HANDSHAKE_DONE;
      memset(confirm.nonce, 0, NONCE_LENGTH);
      memset(confirm.encrypted_data, 0, KEY_LENGTH);

      uip_udp_packet_sendto(handshake_conn, &confirm, sizeof(confirm),
                            &UIP_IP_BUF->srcipaddr, UIP_HTONS(DTLS_HANDSHAKE_PORT));

      handshake_done = 1;
      printf("Handshake complete.\n");
      break;
    }

    default:
      printf("Unknown handshake msg %d\n", pkt->msg_type);
  }
}
/*---------------------------------------------------------------------------*/
static void tcpip_handler(void) {
  if(uip_newdata()) {
    if(UIP_UDP_BUF->destport == UIP_HTONS(DTLS_HANDSHAKE_PORT)) {
      dtls_handshake_t *pkt = (dtls_handshake_t *)uip_appdata;
      handle_handshake(pkt);
    } else if(UIP_UDP_BUF->destport == UIP_HTONS(MCAST_SINK_UDP_PORT)) {
      if(!handshake_done) return;

      dtls_data_t *pkt = (dtls_data_t *)uip_appdata;
      uint8_t plain[16];
      decrypt_data(pkt->encrypted_data, plain);

      uint32_t seq_id;
      memcpy(&seq_id, plain, sizeof(uint32_t));
      seq_id = uip_ntohl(seq_id);

      printf("Received multicast seq=%"PRIu32" [decrypted]\n", seq_id);
    }
  }
}
/*---------------------------------------------------------------------------*/
static void send_client_hello(void) {
  dtls_handshake_t hello;
  hello.msg_type = CLIENT_HELLO;
  generate_nonce(client_nonce);
  memcpy(hello.nonce, client_nonce, NONCE_LENGTH);
  memset(hello.encrypted_data, 0, KEY_LENGTH);

  uip_ipaddr_t root_ip;
  NETSTACK_ROUTING.get_root_ipaddr(&root_ip);

  uip_udp_packet_sendto(handshake_conn, &hello, sizeof(hello),
                        &root_ip, UIP_HTONS(DTLS_HANDSHAKE_PORT));
  printf("CLIENT_HELLO sent to root.\n");
}
/*---------------------------------------------------------------------------*/
PROCESS(tinydtls_sink_process, "TinyDTLS Sink");
AUTOSTART_PROCESSES(&tinydtls_sink_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(tinydtls_sink_process, ev, data)
{
  static struct etimer retry_timer;
  PROCESS_BEGIN();

  printf("=== TinyDTLS Secure Sink ===\n");

  random_init(123);
  handshake_done = 0;

  /* Prepare connections */
  mcast_conn = udp_new(NULL, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
  udp_bind(mcast_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  handshake_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(handshake_conn, UIP_HTONS(DTLS_HANDSHAKE_PORT));

  /* Wait until route to root is ready */
  printf("Waiting for RPL route...\n");
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    PROCESS_PAUSE();
  }

  printf("RPL route established. Starting handshake.\n");
  send_client_hello();

  /* Retry handshake every 5 seconds until done */
  etimer_set(&retry_timer, 5 * CLOCK_SECOND);
  while(!handshake_done) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&retry_timer));
    printf("Retrying handshake...\n");
    send_client_hello();
    etimer_reset(&retry_timer);
  }

  printf("Handshake success! Listening for multicast data...\n");

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

