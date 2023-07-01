#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

/*
* get credit by (daddr, dport) (port of server), 
*/

struct credit_key {
        __be32 daddr;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct credit_key);
	__type(value, s64);
	__uint(max_entries, 10000);
        __uint(pinning, 1);
} credits_map SEC(".maps");

#define MPTCP_SUBFLOWS_MAX 8

#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x > _y ? _x : _y; })

#ifndef __READ_ONCE
#define __READ_ONCE(x)	(*(const volatile typeof(x) *)&(x))
#endif

#define min_t(type, x, y) min((type)(x), (type)(y))

static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

#ifndef div_u64
static inline u64 div_u64(u64 dividend, u32 divisor)
{
	u32 remainder;
	return div_u64_rem(dividend, divisor, &remainder);
}
#endif

#define MAX_TCP_OPTION_SPACE 40
#define MPTCP_SEND_BURST_SIZE		((1 << 16) - \
					 sizeof(struct tcphdr) - \
					 MAX_TCP_OPTION_SPACE - \
					 sizeof(struct ipv6hdr) - \
					 sizeof(struct frag_hdr))

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;
extern void mptcp_sched_data_set_contexts(const struct mptcp_sock *msk,
					  struct mptcp_sched_data *data) __ksym;

extern bool mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;

extern long mptcp_timeout_from_subflow(const struct mptcp_subflow_context *subflow) __ksym;

extern void mptcp_set_timeout(struct sock *sk) __ksym;

extern bool mptcp_subflow_stream_memory_free(const struct mptcp_subflow_context *subflow) __ksym;

SEC("struct_ops/mptcp_sched_creditv2_init")
void BPF_PROG(mptcp_sched_creditv2_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_creditv2_release")
void BPF_PROG(mptcp_sched_creditv2_release, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/bpf_creditv2_data_init")
void BPF_PROG(bpf_creditv2_data_init, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
        mptcp_sched_data_set_contexts(msk, data);
}

#define LIP_1 3232266968
#define LIP_2 3232266895

#define RIP_1 3232266798
#define RIP_2 3232266822

SEC("struct_ops/bpf_creditv2_get_subflowmm")
int BPF_PROG(bpf_creditv2_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
        struct mptcp_subflow_context *subflow;
	u64 min_linger_time = ~(u64)0;
	struct sock *sk = (struct sock *)msk;
	u32 pace, burst, wmem;
	int i, choose_idx = -1;
	struct sock *ssk;
	u64 linger_time;
	long tout = 0;
	u32 local_ip, remote_ip;
        for (i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
                if (data->contexts[i] == NULL) {
                        break;
                }

                subflow = data->contexts[i];
                ssk = subflow->tcp_sock;
		local_ip = bpf_ntohl(ssk->__sk_common.skc_rcv_saddr);
		remote_ip = bpf_ntohl(ssk->__sk_common.skc_daddr);
                tout = max(tout, mptcp_timeout_from_subflow(subflow));

                /*filter subflows*/
		if (!((local_ip == LIP_1 && remote_ip == RIP_1) || (local_ip == LIP_2 && remote_ip == RIP_2))) 
			continue;
                struct credit_key ckey;
                ckey.daddr = ssk->__sk_common.skc_daddr;
                s64 *subflow_credits;
		s64 credits_left;
                subflow_credits = bpf_map_lookup_elem(&credits_map, &ckey);
                if (subflow_credits == NULL) {
                        bpf_printk("bug: credits not found");
                        continue;
                }
		credits_left = __sync_fetch_and_sub(subflow_credits, 1);
                if (credits_left <= 0) {
			continue;
		}
                /*get credits*/

                pace = subflow->avg_pacing_rate;
		if (!pace) {
			/* init pacing rate from socket */
			subflow->avg_pacing_rate = __READ_ONCE(ssk->sk_pacing_rate);
			pace = subflow->avg_pacing_rate;
			if (!pace)
				continue;
		}

		linger_time = div_u64((u64)__READ_ONCE(ssk->sk_wmem_queued) << 32, pace);
		if (linger_time < min_linger_time) {
			min_linger_time = linger_time;
			choose_idx = i;
		}	
        }
        if (choose_idx == -1) 
                return -1;
        /*if no credits left in any subflows defering the transfer*/

	msk->timer_ival = tout > 0 ? tout : 50;

	/* According to the blest algorithm, to avoid HoL blocking for the
	 * faster flow, we need to:
	 * - estimate the faster flow linger time
	 * - use the above to estimate the amount of byte transferred
	 *   by the faster flow
	 * - check that the amount of queued data is greter than the above,
	 *   otherwise do not use the picked, slower, subflow
	 * We select the subflow with the shorter estimated time to flush
	 * the queued mem, which basically ensure the above. We just need
	 * to check that subflow has a non empty cwin.
	 */
	subflow = data->contexts[choose_idx];
	if (!subflow || !mptcp_subflow_stream_memory_free(subflow))
        {
                bpf_printk("warn: subflow is null, or no mptcp subflow stream momory ");
                 //error
		return -1;
        }
	ssk = subflow->tcp_sock;

	burst = min_t(int, MPTCP_SEND_BURST_SIZE, __READ_ONCE(msk->wnd_end) - msk->snd_nxt);
	wmem = __READ_ONCE(ssk->sk_wmem_queued);
	u32 loacl_addr = bpf_ntohl(ssk->__sk_common.skc_rcv_saddr);
	//bpf_printk("debug: local_addr %lu, wem %lu, blest_new burst: %lu, min_lingertime: %llu, choose_idx: %d, tout : %lu", loacl_addr, wmem, burst, min_linger_time, choose_idx, tout);
	if (!burst) {
                mptcp_subflow_set_scheduled(subflow, 1);
                return 0;
        }
		
	subflow->avg_pacing_rate = div_u64((u64)subflow->avg_pacing_rate * wmem +
					   __READ_ONCE(ssk->sk_pacing_rate) * burst,
					   burst + wmem);
	msk->snd_burst = burst;
	mptcp_subflow_set_scheduled(subflow, 1);
        return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops creditv2 = {
	.init		= (void *)mptcp_sched_creditv2_init,
	.release	= (void *)mptcp_sched_creditv2_release,
	.data_init	= (void *)bpf_creditv2_data_init,
	.get_subflow	= (void *)bpf_creditv2_get_subflow,
	.name		= "bpf_creditv2",
};