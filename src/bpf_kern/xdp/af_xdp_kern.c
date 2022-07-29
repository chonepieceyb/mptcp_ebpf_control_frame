/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 64);
} xsks_map SEC(".maps");


SEC("xdp/xdp_sock_prog")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    bpfprintk("queue index %d\n", index);
    if (bpf_map_lookup_elem(&xsks_map, &index)) {
        int ret = bpf_redirect_map(&xsks_map, index, 0);
        bpfprintk("bpf_redirect_map ret : %d\n", ret);
        return ret;
    }

    bpfprintk("not found af xdp\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
