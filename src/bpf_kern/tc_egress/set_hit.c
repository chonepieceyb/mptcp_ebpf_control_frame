#include "common.h"
#include "utils.h"
#include "error.h"

#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_TC_EGRESS_ACTION_NUM);
} tc_egress_actions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1024);
} check_hit SEC(".maps");
#else

BPF_TABLE_PINNED("prog", int, int, tc_egress_actions, MAX_TC_EGRESS_ACTION_NUM, TC_EGRESS_ACTIONS_PATH);
BPF_TABLE_PINNED("hash", u32, int, check_hit, 1024, "/sys/fs/bpf/eMPTCP/check_hit");

#endif

#ifdef NOBCC
SEC("tc")
#endif 
int set_hit(struct __sk_buff *ctx) {

    int res;

    // TC_POLICY_PRE_SEC

    void *data_end = (void*)(__u64)ctx->data_end;
    void *data = (void*)(__u64)ctx->data;
    struct hdr_cursor nh = {.pos = data};
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    int tcphl;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);

    if (res < 0) {
        res = -NOT_TCP;
        goto fail;
    }

    //only work for syn
    if (!tcph->syn||tcph->ack){
        goto fail; 
    }

    res = check_mptcp_opt(&nh, data_end, tcphl-20, MPTCP_SUB_CAPABLE);

    if(res < 0){
        goto fail;
    }

    int ran;
    int hit = 1;
    int miss = 0;
    ran = bpf_ntohs(tcph->seq);
    bpfprint("ran->[%d]\n",ran);
    bpfprint("mod->[%d]\n",ran%100);
    if(ran%100  <= 90){
        bpfprint("HIT!\n");
        bpf_map_update_elem(&check_hit, &tcph->dest, &hit, BPF_ANY);
        // check_hit.update(&tcph->dest, &hit);
        // return TC_ACT_OK;
    }
    else{
        bpfprint("LOSS!\n");
        bpf_map_update_elem(&check_hit, &tcph->dest, &miss, BPF_ANY);
        // check_hit.update(&tcph->dest, &miss);
        // return TC_ACT_OK;
    }

    int *result;
    result = bpf_map_lookup_elem(&check_hit, &tcph->dest);
    if(result == NULL){
        return TC_ACT_OK;
    }
    bpfprint("result->[%d]",*result);
    return TC_ACT_OK;

//     TC_ACTION_POST_SEC
 
// next_action:                          

// #ifdef NOBCC
//     bpf_tail_call(ctx, &tc_egress_actions, NEXT_IDX);
// #else
//     tc_egress_actions.call(ctx, NEXT_IDX);
// #endif 
//     res = -TAIL_CALL_FAIL;                      
//     goto fail;

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