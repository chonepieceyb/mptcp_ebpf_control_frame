#-*- coding:utf-8 -*-

from bcc import BPF
# from libbpf import bpf_obj_pin

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/mptcp.h>
#include <linux/tcp.h>

BPF_TABLE_PINNED("hash", u32, int, mp_levelinfo, 1024, "/sys/fs/bpf/eMPTCP/mp_levelinfo");

int mp_trace(struct pt_regs *ctx, struct sock *sk) {
    u32 mptcp_rem_token;
    int sk_wmem_queued;

	struct tcp_sock *ts = tcp_sk(sk), *subtp;
	struct mptcp_cb *mpcb = ts->mpcb;
    
    mptcp_rem_token = mpcb->mptcp_rem_token;   
    sk_wmem_queued = sk->sk_wmem_queued;

    mp_levelinfo.update(&mptcp_rem_token, &sk_wmem_queued);

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event=("mptcp_write_xmit"), fn_name="mp_trace")

print("Strat Tracing...")
while True:
    try:
        pass
    except KeyboardInterrupt:
        exit()
