#ifndef TUNNEL_H
#define TUNNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>

/*
 * Point-to-Point Tunnel Protocol (Simplified)
 *
 * Architecture:
 *   [Local IF] <-> [Tunnel] <-> [WAN 1,2,3...] <--Internet--> [Peer]
 *
 * 1 frame from local = 1 tunnel packet (no chunking)
 * Both peers run identical code - bidirectional.
 */

#define WAN_MTU             1500    /* Standard WAN MTU */
#define TUNNEL_HEADER_SIZE  17      /* sizeof(data_header_t) */
#define ETH_HEADER_SIZE     14      /* Ethernet header */
#define MAX_FRAME_SIZE      1483    /* Max Ethernet frame = WAN_MTU - TUNNEL_HEADER */
#define LOCAL_MTU           1469    /* MTU for local IF = MAX_FRAME_SIZE - ETH_HEADER */
#define MAX_WAN_INTERFACES  8
#define MAX_FLOWS           4096
#define MAX_PENDING         1024    /* Max pending packets per flow */
#define RETRANSMIT_TIMEOUT  100     /* ms */
#define ACK_TIMEOUT         500     /* ms */
#define MAX_RETRIES         5
#define FLOW_TIMEOUT        30000   /* ms - cleanup stale flows */

/* Packet types */
#define PKT_DATA    0x01
#define PKT_ACK     0x02
#define PKT_NACK    0x03

/* 5-tuple for flow identification */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
} __attribute__((packed)) flow_key_t;

/* DATA packet header: 17 bytes */
typedef struct {
    uint8_t  type;          /* PKT_DATA */
    uint32_t flow_id;       /* Flow identifier (hash of 5-tuple) */
    uint32_t seq;           /* Sequence number within flow */
    uint32_t len;           /* Payload length */
    uint32_t crc32;         /* CRC32 of header + payload */
} __attribute__((packed)) data_header_t;

/* ACK/NACK packet: 9 bytes */
typedef struct {
    uint8_t  type;          /* PKT_ACK or PKT_NACK */
    uint32_t flow_id;
    uint32_t seq;           /* ACK: received seq, NACK: missing seq */
} __attribute__((packed)) ack_pkt_t;

/* Full DATA packet */
typedef struct {
    data_header_t hdr;
    uint8_t data[MAX_FRAME_SIZE];
} packet_t;

/* Pending packet for retransmission */
typedef struct pending_pkt {
    packet_t *pkt;
    uint64_t send_time;
    int retry_count;
    struct pending_pkt *next;
} pending_pkt_t;

/* Flow entry */
typedef struct {
    uint32_t flow_id;
    flow_key_t key;
    bool active;

    /* Send side */
    uint32_t send_seq;              /* Next seq to send */
    pending_pkt_t *pending_head;    /* Packets waiting for ACK */
    pending_pkt_t *pending_tail;
    int pending_count;

    /* Receive side */
    uint32_t recv_seq;              /* Next expected seq */
    bool recv_mask[MAX_PENDING];    /* Received packets bitmap */
    uint32_t recv_base;             /* Base seq for mask */

    uint64_t last_activity;
} flow_t;

/* WAN interface */
typedef struct {
    char name[32];
    int sockfd;
    struct sockaddr_in peer_addr;
    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
} wan_if_t;

/* Tunnel context */
typedef struct {
    char local_if[32];
    int local_fd;

    wan_if_t wan[MAX_WAN_INTERFACES];
    int wan_count;
    int wan_index;

    struct sockaddr_in peer_addr;

    flow_t flows[MAX_FLOWS];

    uint64_t total_tx;
    uint64_t total_rx;
    uint64_t total_retransmit;

    volatile bool running;
} tunnel_t;

/* CRC32 */
uint32_t crc32_calc(const void *data, size_t len);

/* 5-tuple */
int extract_5tuple(const uint8_t *data, size_t len, flow_key_t *key);
uint32_t hash_5tuple(const flow_key_t *key);

/* Tunnel API */
int tunnel_init(tunnel_t *t, const char *config_file);
void tunnel_cleanup(tunnel_t *t);
int tunnel_run(tunnel_t *t);
void tunnel_stop(tunnel_t *t);

#endif /* TUNNEL_H */
