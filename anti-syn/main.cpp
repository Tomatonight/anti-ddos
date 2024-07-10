
#include <string>
#include <regex>
#include <unistd.h>
#include <fcntl.h>
#include <sys/queue.h>
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
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <inttypes.h>
#include "anti.h"
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NB_MBUF 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MBUF_SIZE 2048
unsigned char mac_addr[2][6];
unsigned char local_mac[6];
static uint8_t board_cast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static int nb = 1;
static inline bool mac_equal(char *a, char *b)
{
    return !memcmp(a, b, 6);
}
bool recv_call_back(rte_mbuf *buf, rte_mempool *mempool)
{
    // filter pkt
    rte_ether_hdr *ether = rte_pktmbuf_mtod(buf, rte_ether_hdr *);
    if (mac_equal((char *)board_cast, (char *)ether->dst_addr.addr_bytes))
    {
        //    printf("board cast\n");
        return false;
    }
    if (mac_equal((char *)mac_addr[0], (char *)ether->src_addr.addr_bytes))
    {
        if (parse_mbuf(buf, mempool) < 0)
            return false;
        //   printf("recv %d\n",nb++);
        rte_memcpy(ether->dst_addr.addr_bytes, mac_addr[1], 6);
        rte_memcpy(ether->src_addr.addr_bytes, local_mac, 6);
    }
    else if (mac_equal((char *)mac_addr[1], (char *)ether->src_addr.addr_bytes))
    {
        //   printf("recv b\n");
        rte_memcpy(ether->dst_addr.addr_bytes, mac_addr[0], 6);
        rte_memcpy(ether->src_addr.addr_bytes, local_mac, 6);
    }
    else
    {

        printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ether->src_addr.addr_bytes[0],
               ether->src_addr.addr_bytes[1], ether->src_addr.addr_bytes[2],
               ether->src_addr.addr_bytes[3], ether->src_addr.addr_bytes[4], ether->src_addr.addr_bytes[5]);
        return false;
    }

    return true;
}
int port_init(uint16_t port, rte_mempool *mbuf_pool)
{
    if (port > 0)
        return 0;
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 2, tx_rings = 2;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(rte_eth_conf));
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    //   port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    //  port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    //   port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    rte_eth_macaddr_get(port, (rte_ether_addr *)local_mac);
    printf("port %d mac: %02x:%02x:%02x:%02x:%02x:%02x\n", port, local_mac[0],
           local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;
    //	rte_eth_add_rx_callback(0, 0, rx_callback, NULL);
    /* Enable RX in promiscuous mode for the Ethernet device. */
    //  retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    return 0;
};
void convert_mac(const char *mac_str, unsigned char *mac)
{
    // 使用sscanf解析MAC地址字符串
    int values[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == 6)
    {
        // 将解析的值转换为unsigned char并存储在mac数组中
        for (int i = 0; i < 6; ++i)
        {
            mac[i] = (unsigned char)values[i];
        }
    }
    else
    {
        fprintf(stderr, "Invalid MAC address format\n");
    }
}
void parse_configure()
{

    int fd = open("configure", O_RDONLY);
    char buffer[1024] = {0};
    if (fd < 0)
    {
        rte_exit(-1, "open file err\n");
    }
    int re = read(fd, buffer, 1023);
    if (re < 0)
    {
        rte_exit(-1, "read file err\n");
    }
    std::cmatch match;
    std::regex reg("Host_A:([^ ]*).*Host_B:([^ ]*)");
    if (std::regex_search(buffer, match, reg))
    {
        convert_mac(std::string(match[1]).data(), mac_addr[0]);
        convert_mac(std::string(match[2]).data(), mac_addr[1]);
    }
    else
    {
        rte_exit(-1, "parse configure err\n");
    }
}
int lcore_main(void *pool)
{
    uint16_t port = 0;
    for (;;)
    {
        rte_timer_manage();
        struct rte_mbuf *bufs[BURST_SIZE];
        struct rte_mbuf *send_bufs[BURST_SIZE];
        int idx = 0;

        uint16_t nb_rx = rte_eth_rx_burst(port, rte_lcore_id(), bufs, BURST_SIZE);
        if (nb_rx == 0)
            continue;
        //     if (nb_rx > 0)
        //       printf("recv pkt %d\n", nb_rx);
        uint16_t nb_tx;
        for (int i = 0; i < nb_rx; i++)
        {
            bool re = recv_call_back(bufs[i], *(rte_mempool **)pool);
            if (re)
            {

                send_bufs[idx++] = bufs[i];
            }
            else
            {
                //  printf("drop\n");
                rte_pktmbuf_free(bufs[i]);
            }
        }

        nb_tx = rte_eth_tx_burst(port, rte_lcore_id(), send_bufs, idx);
        //     if (nb_tx > 0)
        //        printf("send pkt %d\n", nb_tx);
        if (unlikely(nb_tx < idx))
        {
            //    printf("free\n");
            uint16_t i;
            for (i = nb_tx; i < idx; i++)
            {
                rte_pktmbuf_free(send_bufs[i]);
            }
        }
    }
    return 0;
}
int main(int argc, char **argv)
{

    parse_configure();
    printf("host a mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_addr[0][0],
           mac_addr[0][1], mac_addr[0][2], mac_addr[0][3], mac_addr[0][4], mac_addr[0][5]);
    printf("host b mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_addr[1][0],
           mac_addr[1][1], mac_addr[1][2], mac_addr[1][3], mac_addr[1][4], mac_addr[1][5]);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
    struct rte_mempool *mbuf_pool;
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NB_MBUF, MBUF_CACHE_SIZE, 0, MBUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
    {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    int portid;
    RTE_ETH_FOREACH_DEV(portid)
    if (port_init(portid, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    int coreid;
    printf("start loop\n");
    rte_timer_subsystem_init();
    anti_init();
    RTE_LCORE_FOREACH_WORKER(coreid)
    {
        rte_eal_remote_launch(lcore_main, &mbuf_pool, coreid);
    }
    lcore_main(&mbuf_pool);
    return 0;
};