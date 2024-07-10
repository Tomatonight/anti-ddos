#pragma once
#include <rte_random.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <rte_common.h>
#include <netinet/if_ether.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_tcp.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_launch.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <rte_eal.h>
#include <rte_timer.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_jhash.h>
#include <rte_debug.h>
#include <rte_hash.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <inttypes.h>
#include <rte_ip.h>
#define SYN_ACK_RETRANSMIT_TIMES 3
#define CHANNEL_KEEP_TIMES 2
#define DROP_FIRST_KEEP_ALIVE 60
#define WHITE_LIST_KEEP_ALIVE 60
#define PARSE_ACCEPT 0
#define PARSE_DROP -1
#define ONE_SECOND_UDP_PKT_LIMIT 100

void anti_init();
int parse_mbuf(rte_mbuf *mbuf, rte_mempool *mempool);
struct key
{
    uint32_t sip;   // net
    uint16_t sport; // net
    uint32_t dip;   // net
    uint16_t dport; // net
    void set_key(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport);
};

class channel
{
public:
    uint32_t sip;      // net
    uint16_t sport;    // net
    uint32_t dip;      // net
    uint16_t dport;    // net
    uint32_t recv_seq; // host
    uint32_t send_seq; // host
    rte_timer my_timer;
    uint8_t retransmit_times;
    bool test_cookie(rte_tcp_hdr *tcp);
    rte_mbuf *alloc_syn_ack(rte_tcp_hdr *tcp, rte_ipv4_hdr *ip, rte_ether_hdr *ether, rte_mempool *mempool);
    rte_mbuf *alloc_reset(rte_tcp_hdr *tcp, rte_ipv4_hdr *ip, rte_ether_hdr *ether, rte_mempool *mempool);
};
class ip_hash
{
private:
    rte_hash *hash_a, *hash_b;
    rte_rwlock_t rw_lock;
    rte_timer timer;
    bool flag = false;

public:
    void init(int timeout);
    void add_ip(uint32_t ip);
    bool test_ip(uint32_t ip);
    void updata_timeout(uint32_t ip);
    void clear_hash();
};

class udp_port_filter
{
public:
    void init();
    rte_hash *protected_ports;
    rte_timer timer;
    rte_rwlock_t rw_lock;
};
void timer_callback_udp_filter(struct rte_timer *timer,void*);
bool udp_filter(uint16_t dport);
void add_channel(channel *channel_);
channel *search_channel(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport);
void remove_channel(channel *channel_);
void timer_callback_channel(struct rte_timer *timer, void *_channel);
void timer_callback_iphash(struct rte_timer *timer, void *ip_hash_);
void send_pkt(rte_mbuf *mbuf);
rte_hash *create_new_iphash();
bool test_checksum(rte_tcp_hdr *tcp, rte_ipv4_hdr *ip);
