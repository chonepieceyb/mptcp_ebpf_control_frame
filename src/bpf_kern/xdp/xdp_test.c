
int xdp_test(struct xdp_md *ctx) {
    bpf_trace_printk("xdp test program1");
    return XDP_PASS;
}
