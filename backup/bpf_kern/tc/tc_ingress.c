#include "common.h"
#include "error.h"

__section("classifier") int tc_inress_main(struct __sk_buff *skb) {
    bpfprintk("test ingress\n");
    return -1;
}

char _license[] SEC("license") = "GPL";
