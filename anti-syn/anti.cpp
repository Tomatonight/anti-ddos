#include "anti.h"
#include <sys/time.h>
#include <time.h>
static rte_hash *sent_syn;
static ip_hash *drop_first;
static ip_hash *white_list;
static uint64_t HZ;
static udp_port_filter *udp_filter_;
static int core_number;
/* DNS（域名系统） - 端口 53
NTP（网络时间协议） - 端口 123
SNMP（简单网络管理协议） - 端口 161
SSDP（简单服务发现协议） - 端口 1900
CHARGEN（字符生成协议） - 端口 19
QOTD（每日名言协议） - 端口 17
RIPv1（路由信息协议版本1） - 端口 520
Memcached - 端口 11211
MSSQL - 端口 1434
CLDAP（轻量目录访问协议） - 端口 389 */
static uint16_t filter_udp_port[] = {53, 123, 161, 1900, 19, 17, 520, 11211, 1434, 389, 0};
struct rte_hash_parameters hash_2 = {
    .name = "sent_syn",
    .entries = 1024 * 5,             // 哈希表的最大条目数
    .key_len = sizeof(uint32_t) * 3, // 键的长度
    .hash_func = rte_jhash,          // 哈希函数
    .hash_func_init_val = 0,         // 哈希函数的初始值
    .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY};
void anti_init()
{

    HZ = rte_get_timer_hz();
    white_list = (ip_hash *)malloc(sizeof(ip_hash));
    white_list->init(WHITE_LIST_KEEP_ALIVE);
    sent_syn = rte_hash_create(&hash_2);
    drop_first = (ip_hash *)malloc(sizeof(ip_hash));
    drop_first->init(DROP_FIRST_KEEP_ALIVE);
    udp_filter_ = new udp_port_filter;
    udp_filter_->init();
}

int parse_mbuf(rte_mbuf *mbuf, rte_mempool *mempool)
{
          printf("recv\n");
    rte_ether_hdr *ether = rte_pktmbuf_mtod(mbuf, rte_ether_hdr *);
    if (rte_cpu_to_be_16(ether->ether_type) != RTE_ETHER_TYPE_IPV4)
        return PARSE_ACCEPT;
    rte_ipv4_hdr *ip = (rte_ipv4_hdr *)(ether + 1);
    switch (ip->next_proto_id)
    {
    case IPPROTO_TCP:
        break;
    case IPPROTO_UDP:
    {
        rte_udp_hdr *udp = (rte_udp_hdr *)((char *)ip + ip->ihl * 4);
        if (udp_filter(ntohs(udp->dst_port)))
            return PARSE_DROP;
        return PARSE_ACCEPT;
    }
    default:
        return PARSE_ACCEPT;
    }
    rte_tcp_hdr *tcp = (rte_tcp_hdr *)((char *)ip + ip->ihl * 4);
    // test if in white list
    // int re = rte_hash_lookup(white_list, &ip->src_addr);
    if (!test_checksum(tcp, ip))
    {
        printf("checksum err\n");
        return PARSE_DROP;
    }
    if (white_list->test_ip(ip->src_addr))
    {
        printf("accept\n");
        white_list->updata_timeout(ip->src_addr);
        return PARSE_ACCEPT;
    }

    if (tcp->tcp_flags == ((uint8_t)0 | RTE_TCP_SYN_FLAG))
    {
        if (drop_first->test_ip(ip->src_addr))
        {
            drop_first->updata_timeout(ip->src_addr);
        }
        else
        {
            drop_first->add_ip(ip->src_addr);
            return PARSE_DROP;
        }
        channel *channel_ = search_channel(ip->src_addr, tcp->src_port, ip->dst_addr, tcp->dst_port);
        if (!channel_)
        {
            channel_ = new channel;
            channel_->sip = ip->src_addr;
            channel_->sport = tcp->src_port;
            channel_->dip = ip->dst_addr;
            channel_->dport = tcp->dst_port;
            channel_->recv_seq = rte_cpu_to_be_32(tcp->sent_seq);
            channel_->send_seq = rte_rand();
            channel_->retransmit_times = SYN_ACK_RETRANSMIT_TIMES;
            rte_timer_init(&channel_->my_timer);
            add_channel(channel_);
        }
        if (channel_->retransmit_times-- > 0)
        {
            rte_timer_reset(&channel_->my_timer, HZ * CHANNEL_KEEP_TIMES, SINGLE, rte_lcore_id(), timer_callback_channel, channel_);
            rte_mbuf *syn_ack = channel_->alloc_syn_ack(tcp, ip, ether, mempool);
            send_pkt(syn_ack);
        }
    }
    else if (tcp->tcp_flags == ((uint8_t)0 | RTE_TCP_ACK_FLAG))
    {
        channel *channel_ = search_channel(ip->src_addr, tcp->src_port, ip->dst_addr, tcp->dst_port);
        if (!channel_)
        {
            return PARSE_DROP;
        }
        if (channel_->test_cookie(tcp))
        {
            rte_mbuf *reset = channel_->alloc_reset(tcp, ip, ether, mempool);
            send_pkt(reset);
            white_list->add_ip(ip->src_addr);
            in_addr addr = {.s_addr = ip->src_addr};
            printf("add %s to white list\n", inet_ntoa(addr));
        }
        else
        {
            printf("ack_seq err\n");
        }
    }
    return PARSE_DROP;
}
void add_channel(channel *channel_)
{
    struct key key;
    key.set_key(channel_->sip, channel_->sport, channel_->dip, channel_->dport);
    rte_hash_add_key_data(sent_syn, &key, channel_);
}
channel *search_channel(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport)
{
    struct key key;
    key.set_key(sip, sport, dip, dport);
    channel *channel_ = nullptr;
    if (rte_hash_lookup_data(sent_syn, &key, (void **)&channel_) < 0)
        return nullptr;
    return channel_;
}
bool channel::test_cookie(rte_tcp_hdr *tcp)
{
    return rte_cpu_to_be_32(tcp->recv_ack) == send_seq + 1;
}
rte_mbuf *channel::alloc_syn_ack(rte_tcp_hdr *tcp_, rte_ipv4_hdr *ip_, rte_ether_hdr *ether_, rte_mempool *mempool)
{
    rte_mbuf *syn_ack = rte_pktmbuf_alloc(mempool);
    if (!syn_ack)
        return nullptr;
    rte_ether_hdr *ether;
    rte_ipv4_hdr *ip;
    rte_tcp_hdr *tcp;
    ether = rte_pktmbuf_mtod(syn_ack, rte_ether_hdr *);
    ip = (rte_ipv4_hdr *)(ether + 1);
    tcp = (rte_tcp_hdr *)(ip + 1);
    int pkt_size = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr);
    syn_ack->pkt_len = pkt_size;
    syn_ack->data_len = pkt_size;
    rte_memcpy(ether->dst_addr.addr_bytes, ether_->src_addr.addr_bytes, 6);
    rte_memcpy(ether->src_addr.addr_bytes, ether->dst_addr.addr_bytes, 6);
    ether->ether_type = ether_->ether_type;
    ip->src_addr = ip_->dst_addr;
    ip->dst_addr = ip_->src_addr;
    ip->ihl = 5;
    ip->version = 4;
    ip->total_length = rte_cpu_to_be_16(sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr));
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->type_of_service = 0;
    ip->hdr_checksum = 0;
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    tcp->sent_seq = rte_cpu_to_be_32(send_seq);
    tcp->recv_ack = rte_cpu_to_be_32((rte_cpu_to_be_32(tcp_->sent_seq)) + 1);
    tcp->rx_win = rte_cpu_to_be_16(40000);
    tcp->tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
    tcp->tcp_urp = 0;
    tcp->src_port = tcp_->dst_port;
    tcp->dst_port = tcp_->src_port;
    tcp->data_off = (sizeof(rte_tcp_hdr) / 4) << 4;
    tcp->cksum = 0;
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
    return syn_ack;
}
rte_mbuf *channel::alloc_reset(rte_tcp_hdr *tcp_, rte_ipv4_hdr *ip_, rte_ether_hdr *ether_, rte_mempool *mempool)
{
    rte_mbuf *reset = rte_pktmbuf_alloc(mempool);
    if (!reset)
        return nullptr;
    rte_ether_hdr *ether;
    rte_ipv4_hdr *ip;
    rte_tcp_hdr *tcp;
    int pkt_size = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr);
    reset->pkt_len = pkt_size;
    reset->data_len = pkt_size;
    ether = rte_pktmbuf_mtod(reset, rte_ether_hdr *);
    ip = (rte_ipv4_hdr *)(ether + 1);
    tcp = (rte_tcp_hdr *)(ip + 1);
    rte_memcpy(ether->dst_addr.addr_bytes, ether_->src_addr.addr_bytes, 6);
    rte_memcpy(ether->src_addr.addr_bytes, ether->dst_addr.addr_bytes, 6);
    ether->ether_type = ether_->ether_type;
    ip->src_addr = ip_->dst_addr;
    ip->dst_addr = ip_->src_addr;
    ip->version = 4;
    ip->ihl = 5;
    ip->total_length = rte_cpu_to_be_16(sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr));
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->type_of_service = 0;
    ip->hdr_checksum = 0;
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    tcp->sent_seq = rte_cpu_to_be_32(send_seq + 1);
    tcp->recv_ack = rte_cpu_to_be_32((rte_cpu_to_be_32(tcp_->sent_seq)));
    tcp->rx_win = rte_cpu_to_be_16(40000);
    tcp->tcp_flags = RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG;
    tcp->tcp_urp = 0;
    tcp->src_port = tcp_->dst_port;
    tcp->dst_port = tcp_->src_port;
    tcp->data_off = (sizeof(rte_tcp_hdr) / 4) << 4;
    tcp->cksum = 0;
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
    return reset;
}
void key::set_key(uint32_t sip_, uint16_t sport_, uint32_t dip_, uint16_t dport_)
{
    sip = sip_;
    dip = dip_;
    sport = sport_;
    dport = dport_;
}
void remove_channel(channel *channel_)
{
    struct key key;
    key.set_key(channel_->sip, channel_->sport, channel_->dip, channel_->dport);
    rte_hash_del_key(sent_syn, &key);
}
void timer_callback_channel(struct rte_timer *timer, void *_channel)
{

    // printf("channel core: %d \n", rte_lcore_id());
    channel *channel_ = (channel *)_channel;
    remove_channel(channel_);
    rte_timer_stop(&channel_->my_timer);
    delete channel_;
}
void timer_callback_iphash(struct rte_timer *timer, void *ip_hash_)
{
    // printf("core: %d \n", rte_lcore_id());
    ip_hash *hash = (ip_hash *)ip_hash_;
    hash->clear_hash();
}
void send_pkt(rte_mbuf *mbuf)
{
    for (;;)
    {
        int nb_tx = rte_eth_tx_burst(0, rte_lcore_id(), &mbuf, 1);
        if (nb_tx > 0)
            break;
    }
}
void ip_hash::init(int timeout)
{
    hash_a = create_new_iphash();
    hash_b = create_new_iphash();
    rte_rwlock_init(&rw_lock);
    rte_timer_init(&timer);
    rte_timer_reset(&timer, timeout * HZ, PERIODICAL, LCORE_ID_ANY, timer_callback_iphash, (void *)this);
}
void ip_hash::add_ip(uint32_t ip)
{
    rte_rwlock_read_lock(&rw_lock);
    //  printf("add ip\n");
    if (flag)
        rte_hash_add_key(hash_a, &ip);
    else
        rte_hash_add_key(hash_b, &ip);
    rte_rwlock_read_unlock(&rw_lock);
}
bool ip_hash::test_ip(uint32_t ip)
{
    rte_rwlock_read_lock(&rw_lock);
    bool re = rte_hash_lookup(hash_a, &ip) >= 0 || rte_hash_lookup(hash_b, &ip) >= 0;
    rte_rwlock_read_unlock(&rw_lock);
    return re;
}
void ip_hash::clear_hash()
{
    // printf("clear\n");
    rte_rwlock_write_lock(&rw_lock);
    struct rte_hash_parameters new_hash = {
        .name = "new_hash",
        .entries = 1024 * 5,         // 哈希表的最大条目数
        .key_len = sizeof(uint32_t), // 键的长度
        .hash_func = rte_jhash,      // 哈希函数
        .hash_func_init_val = 0,     // 哈希函数的初始值
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY};

    if (flag)
    {
        flag = false;
        rte_hash_free(hash_a);
        hash_a = create_new_iphash();
    }
    else
    {
        flag = true;
        rte_hash_free(hash_b);
        hash_b = create_new_iphash();
    }
    rte_rwlock_write_unlock(&rw_lock);
}
void ip_hash::updata_timeout(uint32_t ip)
{
    // printf("updata ip\n");
    add_ip(ip);
}
rte_hash *create_new_iphash()
{
    static uint32_t id;
    char hash_name[20] = {0};
    sprintf(hash_name, "hash_name_%d", id++);
    //  printf("create %s\n",hash_name);
    struct rte_hash_parameters iphash = {
        .name = hash_name,
        .entries = 1024 * 5,         // 哈希表的最大条目数
        .key_len = sizeof(uint32_t), // 键的长度
        .hash_func = rte_jhash,      // 哈希函数
        .hash_func_init_val = 0,     // 哈希函数的初始值
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY};
    return rte_hash_create(&iphash);
}
bool test_checksum(rte_tcp_hdr *tcp, rte_ipv4_hdr *ip)
{
    uint16_t ip_checksum = ip->hdr_checksum;
    ip->hdr_checksum = 0;
    uint16_t tcp_checksum = tcp->cksum;
    tcp->cksum = 0;
    bool re = (rte_ipv4_cksum(ip) == ip_checksum) && (rte_ipv4_udptcp_cksum(ip, tcp) == tcp_checksum);
    ip->hdr_checksum = ip_checksum;
    tcp->cksum = tcp_checksum;
    return re;
}
void udp_port_filter::init()
{
    struct rte_hash_parameters iphash = {
        .name = "udp_filter",
        .entries = 1024 * 5,
        .key_len = sizeof(uint16_t), // 键的长度
        .hash_func = rte_jhash,      // 哈希函数
        .hash_func_init_val = 0,     // 哈希函数的初始值
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY};
    protected_ports = rte_hash_create(&iphash);
    for (int i = 0; filter_udp_port[i]; i++)
    {
        rte_hash_add_key_data(protected_ports, &filter_udp_port[i], (void *)(0));
    }
    rte_rwlock_init(&rw_lock);
    rte_timer_init(&timer);
    rte_timer_reset(&udp_filter_->timer, HZ * 2, PERIODICAL, LCORE_ID_ANY, timer_callback_udp_filter, NULL);
};
void timer_callback_udp_filter(struct rte_timer *timer, void *)
{
    for (int i = 0; filter_udp_port[i]; i++)
    {
        rte_hash_add_key_data(udp_filter_->protected_ports, &filter_udp_port[i], (void *)(0));
    }
}
bool udp_filter(uint16_t dport)
{
    printf("recv dport %d\n",dport);
    int visit_nb;
    bool re = false;
    if (rte_hash_lookup_data(udp_filter_->protected_ports, &dport, (void **)&visit_nb) >= 0)
    {
        if (visit_nb++ > ONE_SECOND_UDP_PKT_LIMIT)
        {
            printf("filter\n");
            re = true;
        }
        rte_hash_add_key_data(udp_filter_->protected_ports, &dport, (void *)visit_nb);
    }
    return re;
}