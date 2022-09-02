#include "umem.h"
#include "xsk_sock.h"
#include "xsk_rings.h"
#include <list> 
#include <memory>

extern "C" {
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf.h>

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 n)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), n);
}


static bool process_packet(void* data, uint32_t len)
{
    if (data == nullptr || data == NULL ) {
        std::cout << "data is null \b";
    }
    uint8_t *pkt = reinterpret_cast<std::uint8_t*>(data);
       
    uint8_t tmp_mac[ETH_ALEN];
    struct in6_addr tmp_ip;
    struct ethhdr *eth = (struct ethhdr *) pkt;
    struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
    struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);


    if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
	len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
	ipv6->nexthdr != IPPROTO_ICMPV6 ||
	icmp->icmp6_type != ICMPV6_ECHO_REQUEST) {
	return false;
    }

    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);
    memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
    memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
    memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));

    icmp->icmp6_type = ICMPV6_ECHO_REPLY;

    csum_replace2(&icmp->icmp6_cksum,
        htons(ICMPV6_ECHO_REQUEST << 8),
	htons(ICMPV6_ECHO_REPLY << 8));
    return true;
}

}

using namespace eMPTCP::xsk;

int main() {
    std::uint32_t batch_size = 64;
    std::list<XDPDesc> batch_data;
        
    auto umem = std::make_shared<Umem>(UmemConfig());
    std::string ifname = "ens34";
    int queue = 0;
    auto xsk_conf = XSKSocketConfig();
    //xsk_conf.bind_flags = 0;
    //xsk_conf.libxdp_flags = 0;   
    XSKSocket xsk(ifname, queue, umem, xsk_conf);
    std::cout << "xsk fd: " << xsk.fd() << "\n";
    //add fd to bpf map 

    int mapfd = bpf_obj_get("/sys/fs/bpf/xsks_map");
    int xsk_fd = xsk.fd();
    if (mapfd < 0) {
        std::cout << "get xsks_map failed\n";
        exit(-1) ;
    }   
    int ret = bpf_map_update_elem(mapfd, &queue, &xsk_fd, 0);
    if (ret < 0) {
        std::cout << "update xsk map failed\n";
        exit(-1);
    }

    utils::TermSignal::regist();

    //std::uint32_t recv = 0;
    while (true) {
        try {
            xsk.recv(std::back_inserter(batch_data), batch_size);
            //process batch data
            for (auto iter = batch_data.begin(); iter != batch_data.end();) {
                auto addr = iter->addr;
                auto len = iter->len;
                bool accept = process_packet(umem->get_data(addr), len); 
                if (!accept) {
                    xsk.free_frame(addr);
                    iter = batch_data.erase(iter);
                } else {
                    iter++;
                }
            }        
            xsk.send(batch_data.begin(), batch_data.size());
            batch_data.clear();
        } catch (const errors::KeyboardInterrupt &e) {
            break;
        }
    }
    

    return 0;
}
