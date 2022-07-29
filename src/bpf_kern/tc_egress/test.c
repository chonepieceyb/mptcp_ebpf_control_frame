#include "common.h"

SEC("tc")
int scancb(struct __sk_buff *ctx) {
    //scan cb 
    __u32 curr_id = ctx->cb[1];
    bpfprintk("target %d", curr_id);
    return 0;
}
char _license[] SEC("license") = "GPL";
