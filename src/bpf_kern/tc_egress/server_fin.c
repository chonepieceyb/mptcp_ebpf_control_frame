#include "common.h"
#include "utils.h"
#include "error.h"

struct fin_info
{
    __u32 init_seq;
    __u32 fin_seq;
    __u32 fin_ack;
    int flag;
}__attribute__((__packed__));


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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, struct fin_info);
    __uint(max_entries, 1024);
} check_fin SEC(".maps");
#else

BPF_TABLE_PINNED("prog", int, int, tc_egress_actions, MAX_TC_EGRESS_ACTION_NUM, TC_EGRESS_ACTIONS_PATH);
BPF_TABLE_PINNED("hash", u32, int, check_hit, 1024, "/sys/fs/bpf/eMPTCP/check_hit");
BPF_TABLE_PINNED("hash", u32, int, struct fin_info, 1024, "/sys/fs/bpf/eMPTCP/check_fin");

#endif

#ifdef NOBCC
SEC("tc")
#endif
int server_fin(struct __sk_buff *ctx) {
    int res;

    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct fin_info fin_info;
    //memset?
    __builtin_memset(&fin_info, 0, sizeof(struct fin_info));

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res < 0) {
        res = -NOT_TCP;
        goto fail;
    }

    // no tcp option
    if (tcphl <= 20) {
        return TC_ACT_OK;
    }

    int *result;
    result = bpf_map_lookup_elem(&check_hit, &tcph->dest);

    if(result == NULL){
        return TC_ACT_OK;
    }

    int ifhit;
    ifhit = *result;

    if (tcph->fin && ifhit) {
        struct fin_info *fin_get;

        fin_get = bpf_map_lookup_elem(&check_fin, &tcph->dest);

        __be16 *old_begin1, *new_begin1;
        __be16 *old_begin2, *new_begin2;

        __be32 new_finseq = fin_get->fin_ack;
        __be32 new_finack = bpf_htonl(bpf_ntohl(fin_get->fin_seq) + 1);

        old_begin1 = (__be16*)(&tcph->seq);
        new_begin1 = (__be16*)(&new_finseq);

        old_begin2 = (__be16*)(&tcph->ack_seq);
        new_begin2 = (__be16*)(&new_finack);

        #pragma unroll 2
        for (int i = 0; i < 2; i++) {
            csum_replace2(&tcph->check, *old_begin1, *new_begin1);
            old_begin1++;
            new_begin1++;
        }

        #pragma unroll 2
        for (int i = 0; i < 2; i++) {
            csum_replace2(&tcph->check, *old_begin2, *new_begin2);
            old_begin2++;
            new_begin2++;
        }

        tcph->seq = new_finseq;
        tcph->ack_seq =new_finack;

        fin_get->flag = 1;
        bpf_map_update_elem(&check_fin, &tcph->dest, &fin_get, BPF_ANY);

        return TC_ACT_OK;
    }


out_of_bound:
fail: 
    return TC_ACT_UNSPEC;

exit:
    return TC_ACT_UNSPEC;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
