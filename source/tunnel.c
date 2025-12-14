#include "tunnel.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>

/* CRC32 table */
static const uint32_t crc32_tab[256] = {
    0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
    0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,
    0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
    0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
    0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
    0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
    0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
    0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
    0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
    0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,
    0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
    0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
    0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,
    0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
    0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
    0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,
    0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,
    0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
    0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,
    0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,
    0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
    0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,
    0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,
    0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,
    0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
    0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,
    0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,
    0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
    0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,
    0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,
    0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,
    0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D
};

static uint64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

uint32_t crc32_calc(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = crc32_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

static uint32_t calc_packet_crc(const packet_t *pkt) {
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t *p;

    crc = crc32_tab[(crc ^ pkt->hdr.type) & 0xFF] ^ (crc >> 8);

    p = (const uint8_t *)&pkt->hdr.flow_id;
    for (int i = 0; i < 4; i++) crc = crc32_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);

    p = (const uint8_t *)&pkt->hdr.seq;
    for (int i = 0; i < 4; i++) crc = crc32_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);

    p = (const uint8_t *)&pkt->hdr.len;
    for (int i = 0; i < 4; i++) crc = crc32_tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);

    for (uint32_t i = 0; i < pkt->hdr.len && i < MAX_FRAME_SIZE; i++) {
        crc = crc32_tab[(crc ^ pkt->data[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

static bool verify_packet(const packet_t *pkt) {
    return calc_packet_crc(pkt) == pkt->hdr.crc32;
}

/* Extract 5-tuple from Ethernet frame */
int extract_5tuple(const uint8_t *data, size_t len, flow_key_t *key) {
    if (len < sizeof(struct ethhdr)) return -1;

    struct ethhdr *eth = (struct ethhdr *)data;
    uint16_t eth_type = ntohs(eth->h_proto);

    const uint8_t *ptr = data + sizeof(struct ethhdr);
    size_t remaining = len - sizeof(struct ethhdr);

    /* Skip VLAN tags */
    while (eth_type == 0x8100 || eth_type == 0x88A8) {
        if (remaining < 4) return -1;
        eth_type = ntohs(*(uint16_t *)(ptr + 2));
        ptr += 4;
        remaining -= 4;
    }

    /* Only IPv4 */
    if (eth_type != ETH_P_IP) return -1;
    if (remaining < sizeof(struct iphdr)) return -1;

    struct iphdr *ip = (struct iphdr *)ptr;
    if (ip->version != 4) return -1;

    size_t ip_hlen = ip->ihl * 4;
    if (remaining < ip_hlen) return -1;

    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->protocol = ip->protocol;
    key->src_port = 0;
    key->dst_port = 0;

    ptr += ip_hlen;
    remaining -= ip_hlen;

    if (ip->protocol == IPPROTO_TCP && remaining >= sizeof(struct tcphdr)) {
        struct tcphdr *tcp = (struct tcphdr *)ptr;
        key->src_port = ntohs(tcp->source);
        key->dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP && remaining >= sizeof(struct udphdr)) {
        struct udphdr *udp = (struct udphdr *)ptr;
        key->src_port = ntohs(udp->source);
        key->dst_port = ntohs(udp->dest);
    }

    return 0;
}

/* Hash 5-tuple to flow_id */
uint32_t hash_5tuple(const flow_key_t *key) {
    uint32_t hash = 0;
    hash ^= key->src_ip;
    hash ^= key->dst_ip;
    hash ^= ((uint32_t)key->src_port << 16) | key->dst_port;
    hash ^= key->protocol;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);
    return hash ? hash : 1;
}

static int set_interface_mtu(const char *ifname, int mtu) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;

    int ret = ioctl(fd, SIOCSIFMTU, &ifr);
    close(fd);
    return ret;
}

static int init_local_socket(tunnel_t *t) {
    /* Set MTU to LOCAL_MTU (1469) so tunnel packets fit in WAN MTU (1500) */
    set_interface_mtu(t->local_if, LOCAL_MTU);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, t->local_if, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    t->local_fd = fd;
    return 0;
}

static int init_wan_socket(wan_if_t *wan, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    wan->sockfd = fd;
    return 0;
}

static int key_equal(const flow_key_t *a, const flow_key_t *b) {
    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->protocol == b->protocol;
}

static flow_t* find_flow_by_key(tunnel_t *t, const flow_key_t *key) {
    uint32_t hash = hash_5tuple(key);
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (t->flows[i].active && t->flows[i].flow_id == hash && key_equal(&t->flows[i].key, key)) {
            return &t->flows[i];
        }
    }
    return NULL;
}

static flow_t* find_flow_by_id(tunnel_t *t, uint32_t flow_id) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (t->flows[i].active && t->flows[i].flow_id == flow_id) {
            return &t->flows[i];
        }
    }
    return NULL;
}

static flow_t* alloc_flow(tunnel_t *t, const flow_key_t *key) {
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (!t->flows[i].active) {
            flow_t *f = &t->flows[i];
            memset(f, 0, sizeof(flow_t));
            f->flow_id = hash_5tuple(key);
            f->key = *key;
            f->active = true;
            f->last_activity = get_time_ms();
            return f;
        }
    }
    return NULL;
}

static void free_pending(pending_pkt_t *p) {
    while (p) {
        pending_pkt_t *next = p->next;
        if (p->pkt) free(p->pkt);
        free(p);
        p = next;
    }
}

static void free_flow(flow_t *f) {
    free_pending(f->pending_head);
    f->pending_head = NULL;
    f->pending_tail = NULL;
    f->pending_count = 0;
    f->active = false;
}

int tunnel_init(tunnel_t *t, const char *config_file) {
    memset(t, 0, sizeof(tunnel_t));
    t->running = false;
    t->local_fd = -1;

    FILE *fp = fopen(config_file, "r");
    if (!fp) return -1;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char key[64], val[128];
        if (sscanf(line, "%63s %127s", key, val) != 2) continue;

        if (strcmp(key, "local") == 0) {
            strncpy(t->local_if, val, sizeof(t->local_if) - 1);
        } else if (strcmp(key, "peer") == 0) {
            char ip[64];
            int port;
            if (sscanf(val, "%63[^:]:%d", ip, &port) == 2) {
                t->peer_addr.sin_family = AF_INET;
                inet_pton(AF_INET, ip, &t->peer_addr.sin_addr);
                t->peer_addr.sin_port = htons(port);
            }
        } else if (strcmp(key, "wan") == 0) {
            if (t->wan_count < MAX_WAN_INTERFACES) {
                char name[32];
                int port;
                if (sscanf(val, "%31[^:]:%d", name, &port) == 2) {
                    strncpy(t->wan[t->wan_count].name, name, sizeof(t->wan[0].name) - 1);
                    if (init_wan_socket(&t->wan[t->wan_count], port) == 0) {
                        t->wan[t->wan_count].peer_addr = t->peer_addr;
                        t->wan[t->wan_count].peer_addr.sin_port = htons(port);
                        t->wan_count++;
                    }
                }
            }
        }
    }
    fclose(fp);

    if (t->wan_count == 0) return -1;
    if (init_local_socket(t) < 0) return -1;

    return 0;
}

void tunnel_cleanup(tunnel_t *t) {
    t->running = false;

    if (t->local_fd >= 0) {
        close(t->local_fd);
        t->local_fd = -1;
    }

    for (int i = 0; i < t->wan_count; i++) {
        if (t->wan[i].sockfd >= 0) {
            close(t->wan[i].sockfd);
            t->wan[i].sockfd = -1;
        }
    }

    for (int i = 0; i < MAX_FLOWS; i++) {
        if (t->flows[i].active) {
            free_flow(&t->flows[i]);
        }
    }
}

/* Send packet via WAN (round-robin) */
static int send_via_wan(tunnel_t *t, const packet_t *pkt) {
    wan_if_t *wan = &t->wan[t->wan_index];
    t->wan_index = (t->wan_index + 1) % t->wan_count;

    size_t pkt_len = sizeof(data_header_t) + pkt->hdr.len;
    ssize_t sent = sendto(wan->sockfd, pkt, pkt_len, 0,
                          (struct sockaddr *)&wan->peer_addr, sizeof(wan->peer_addr));

    if (sent > 0) {
        wan->tx_packets++;
        wan->tx_bytes += sent;
        t->total_tx++;
        return 0;
    }
    return -1;
}

/* Send raw data to local interface */
static int send_to_local(tunnel_t *t, const uint8_t *data, size_t len) {
    if (t->local_fd < 0) return -1;
    ssize_t sent = write(t->local_fd, data, len);
    return (sent > 0) ? 0 : -1;
}

/* Handle packet from local interface */
static int handle_local_packet(tunnel_t *t, const uint8_t *data, size_t len) {
    if (len > MAX_FRAME_SIZE) return -1;

    flow_key_t key;
    if (extract_5tuple(data, len, &key) < 0) {
        memset(&key, 0, sizeof(key));
        key.src_ip = crc32_calc(data, len > 64 ? 64 : len);
    }

    flow_t *f = find_flow_by_key(t, &key);
    if (!f) {
        f = alloc_flow(t, &key);
        if (!f) return -1;
    }

    /* Create tunnel packet */
    packet_t *pkt = (packet_t *)malloc(sizeof(packet_t));
    if (!pkt) return -1;

    pkt->hdr.type = PKT_DATA;
    pkt->hdr.flow_id = f->flow_id;
    pkt->hdr.seq = f->send_seq++;
    pkt->hdr.len = len;
    memcpy(pkt->data, data, len);
    pkt->hdr.crc32 = calc_packet_crc(pkt);

    /* Send immediately */
    send_via_wan(t, pkt);

    /* Add to pending list for retransmission */
    pending_pkt_t *pending = (pending_pkt_t *)malloc(sizeof(pending_pkt_t));
    if (pending) {
        pending->pkt = pkt;
        pending->send_time = get_time_ms();
        pending->retry_count = 0;
        pending->next = NULL;

        if (f->pending_tail) {
            f->pending_tail->next = pending;
            f->pending_tail = pending;
        } else {
            f->pending_head = f->pending_tail = pending;
        }
        f->pending_count++;
    } else {
        free(pkt);
    }

    f->last_activity = get_time_ms();
    return 0;
}

/* Send ACK/NACK (9 bytes) */
static int send_ack(tunnel_t *t, uint32_t flow_id, uint32_t seq) {
    ack_pkt_t ack;
    ack.type = PKT_ACK;
    ack.flow_id = flow_id;
    ack.seq = seq;

    wan_if_t *wan = &t->wan[t->wan_index];
    t->wan_index = (t->wan_index + 1) % t->wan_count;

    ssize_t sent = sendto(wan->sockfd, &ack, sizeof(ack), 0,
                          (struct sockaddr *)&wan->peer_addr, sizeof(wan->peer_addr));
    if (sent > 0) {
        wan->tx_packets++;
        wan->tx_bytes += sent;
        return 0;
    }
    return -1;
}

static int send_nack(tunnel_t *t, uint32_t flow_id, uint32_t seq) {
    ack_pkt_t nack;
    nack.type = PKT_NACK;
    nack.flow_id = flow_id;
    nack.seq = seq;

    wan_if_t *wan = &t->wan[t->wan_index];
    t->wan_index = (t->wan_index + 1) % t->wan_count;

    ssize_t sent = sendto(wan->sockfd, &nack, sizeof(nack), 0,
                          (struct sockaddr *)&wan->peer_addr, sizeof(wan->peer_addr));
    if (sent > 0) {
        wan->tx_packets++;
        wan->tx_bytes += sent;
        return 0;
    }
    return -1;
}

/* Handle packet from WAN */
static int handle_wan_packet(tunnel_t *t, int wan_idx, const uint8_t *data, size_t len) {
    if (len < 1) return -1;

    uint8_t type = data[0];

    t->wan[wan_idx].rx_packets++;
    t->wan[wan_idx].rx_bytes += len;
    t->total_rx++;

    switch (type) {
        case PKT_DATA: {
            if (len < sizeof(data_header_t)) return -1;

            packet_t pkt;
            size_t copy_len = (len > sizeof(packet_t)) ? sizeof(packet_t) : len;
            memcpy(&pkt, data, copy_len);

            if (!verify_packet(&pkt)) return -1;

            flow_t *f = find_flow_by_id(t, pkt.hdr.flow_id);
            if (!f) {
                flow_key_t dummy_key = {0};
                dummy_key.src_ip = pkt.hdr.flow_id;
                f = alloc_flow(t, &dummy_key);
                if (!f) return -1;
                f->flow_id = pkt.hdr.flow_id;
                f->recv_base = pkt.hdr.seq;
            }

            uint32_t idx = pkt.hdr.seq - f->recv_base;
            if (idx < MAX_PENDING) {
                if (!f->recv_mask[idx]) {
                    f->recv_mask[idx] = true;
                    send_to_local(t, pkt.data, pkt.hdr.len);
                }
            }

            if (pkt.hdr.seq >= f->recv_seq) {
                f->recv_seq = pkt.hdr.seq + 1;
            }

            send_ack(t, pkt.hdr.flow_id, pkt.hdr.seq);
            f->last_activity = get_time_ms();
            break;
        }

        case PKT_ACK: {
            if (len < sizeof(ack_pkt_t)) return -1;

            ack_pkt_t ack;
            memcpy(&ack, data, sizeof(ack_pkt_t));

            flow_t *f = find_flow_by_id(t, ack.flow_id);
            if (f) {
                pending_pkt_t *prev = NULL;
                pending_pkt_t *curr = f->pending_head;

                while (curr) {
                    if (curr->pkt && curr->pkt->hdr.seq == ack.seq) {
                        if (prev) {
                            prev->next = curr->next;
                        } else {
                            f->pending_head = curr->next;
                        }
                        if (curr == f->pending_tail) {
                            f->pending_tail = prev;
                        }
                        free(curr->pkt);
                        free(curr);
                        f->pending_count--;
                        break;
                    }
                    prev = curr;
                    curr = curr->next;
                }
                f->last_activity = get_time_ms();
            }
            break;
        }

        case PKT_NACK: {
            if (len < sizeof(ack_pkt_t)) return -1;

            ack_pkt_t nack;
            memcpy(&nack, data, sizeof(ack_pkt_t));

            flow_t *f = find_flow_by_id(t, nack.flow_id);
            if (f) {
                pending_pkt_t *curr = f->pending_head;
                while (curr) {
                    if (curr->pkt && curr->pkt->hdr.seq == nack.seq) {
                        send_via_wan(t, curr->pkt);
                        curr->send_time = get_time_ms();
                        curr->retry_count++;
                        t->total_retransmit++;
                        break;
                    }
                    curr = curr->next;
                }
                f->last_activity = get_time_ms();
            }
            break;
        }
    }

    return 0;
}

/* Check timeouts and cleanup */
static void check_timeouts(tunnel_t *t) {
    uint64_t now = get_time_ms();

    for (int i = 0; i < MAX_FLOWS; i++) {
        flow_t *f = &t->flows[i];
        if (!f->active) continue;

        /* Cleanup stale flows */
        if ((now - f->last_activity) > FLOW_TIMEOUT) {
            free_flow(f);
            continue;
        }

        /* Retransmit timed-out packets */
        pending_pkt_t *prev = NULL;
        pending_pkt_t *curr = f->pending_head;

        while (curr) {
            pending_pkt_t *next = curr->next;

            if ((now - curr->send_time) > ACK_TIMEOUT) {
                if (curr->retry_count >= MAX_RETRIES) {
                    /* Give up on this packet */
                    if (prev) {
                        prev->next = next;
                    } else {
                        f->pending_head = next;
                    }
                    if (curr == f->pending_tail) {
                        f->pending_tail = prev;
                    }
                    free(curr->pkt);
                    free(curr);
                    f->pending_count--;
                } else {
                    /* Retransmit */
                    send_via_wan(t, curr->pkt);
                    curr->send_time = now;
                    curr->retry_count++;
                    t->total_retransmit++;
                    prev = curr;
                }
            } else {
                prev = curr;
            }
            curr = next;
        }

        /* Slide receive window if needed */
        while (f->recv_mask[0] && f->recv_base < f->recv_seq) {
            memmove(f->recv_mask, f->recv_mask + 1, (MAX_PENDING - 1) * sizeof(bool));
            f->recv_mask[MAX_PENDING - 1] = false;
            f->recv_base++;
        }
    }
}

int tunnel_run(tunnel_t *t) {
    t->running = true;
    uint8_t buf[65536];
    fd_set readfds;
    struct timeval tv;
    uint64_t last_check = 0;

    while (t->running) {
        FD_ZERO(&readfds);
        int maxfd = t->local_fd;
        FD_SET(t->local_fd, &readfds);

        for (int i = 0; i < t->wan_count; i++) {
            FD_SET(t->wan[i].sockfd, &readfds);
            if (t->wan[i].sockfd > maxfd) maxfd = t->wan[i].sockfd;
        }

        tv.tv_sec = 0;
        tv.tv_usec = 10000;

        int ret = select(maxfd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (FD_ISSET(t->local_fd, &readfds)) {
            ssize_t n = read(t->local_fd, buf, sizeof(buf));
            if (n > 0) {
                handle_local_packet(t, buf, n);
            }
        }

        for (int i = 0; i < t->wan_count; i++) {
            if (FD_ISSET(t->wan[i].sockfd, &readfds)) {
                struct sockaddr_in from;
                socklen_t fromlen = sizeof(from);
                ssize_t n = recvfrom(t->wan[i].sockfd, buf, sizeof(buf), 0,
                                     (struct sockaddr *)&from, &fromlen);
                if (n > 0) {
                    handle_wan_packet(t, i, buf, n);
                }
            }
        }

        uint64_t now = get_time_ms();
        if (now - last_check > 50) {
            check_timeouts(t);
            last_check = now;
        }
    }

    return 0;
}

void tunnel_stop(tunnel_t *t) {
    t->running = false;
}
