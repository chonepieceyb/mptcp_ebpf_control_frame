#include "common.h"
#include "utils.h"
#include "error.h"

#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })


#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_TC_EGRESS_ACTION_NUM);
} tc_egress_actions SEC(".maps");
#else

BPF_TABLE_PINNED("prog", int, int, tc_egress_actions, MAX_TC_EGRESS_ACTION_NUM, TC_EGRESS_ACTIONS_PATH);

#endif

#ifdef NOBCC
SEC("tc")
#endif 
int msg_diff_action(struct __sk_buff *ctx) {
    int res;

    void *data_end = (void*)(__u64)ctx->data_end;
    void *data = (void*)(__u64)ctx->data;
    struct hdr_cursor nh = {.pos = data};
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    int tcphl;
    // int eth_type;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);

    if (res < 0) {
        res = -NOT_TCP;
        goto fail;
    }

    if (tcph->syn){
        return TC_ACT_OK; 
    }

    char *payload = data + sizeof(*eth) + sizeof(*iph) + tcphl;

    if((void*)(payload+1) > data_end){
        goto out_of_bound;
    }

    // bpfprint("payload1:[%d]\n", payload[0]);
    // bpfprint("payload2:[%d]\n", payload[1]);
    // bpfprint("payload3:[%d]\n", payload[2]);
    
    // B1
    //src1 00:0c:29:e2:0a:34
    unsigned char dst_1[ETH_ALEN] = {0x00,0x0c,0x29,0xc8,0xb8,0x90};
    // B2
    //src2 00:0c:29:e2:0a:3e
    unsigned char dst_2[ETH_ALEN] = {0x00,0x0c,0x29,0xc8,0xb8,0x9a};
    // unsigned char dst_2[ETH_ALEN] = {0x00,0x0c,0x29,0xc8,0xb8,0xa4};
    // unsigned ifindex_1 = 2;
    // unsigned ifindex_2 = 3;

    //192.168.71.138 -1975015232
    if(payload[0]==97 && iph->daddr==-1975015232 && eth->h_dest[5]!=0x90){
        memcpy(eth->h_dest, dst_1, ETH_ALEN);
        return bpf_redirect(2, 0);
        // return TC_ACT_OK;
    }
    //C0A8478A
    // 192.168.3.66
    else if (payload[0]==98 && iph->daddr==1107536064 && eth->h_dest[5]!=0x9a)
    {   
        memcpy(eth->h_dest, dst_2, ETH_ALEN);
        return bpf_redirect(3, 0);
    }
    else{
        // bpfprint("continue\n");
        goto fail;
    }

out_of_bound:
fail: 
    return TC_ACT_UNSPEC;

exit:
    //bpf_trace_printk("finish!");
    return TC_ACT_UNSPEC;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif
