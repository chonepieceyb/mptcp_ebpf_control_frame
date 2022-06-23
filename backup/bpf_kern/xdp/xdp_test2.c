int xdp_test2(struct xdp_md *ctx) {
    bpf_trace_printk("xdp test program2");
    return XDP_PASS;
}
