#include "mptcp_sched.h"
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define MPTCP_SUBFLOWS_MAX 8

#define SSK_MODE_ACTIVE	0
#define SSK_MODE_BACKUP	1
#define SSK_MODE_MAX 2

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;
extern void mptcp_sched_data_set_contexts(const struct mptcp_sock *msk,
					  struct mptcp_sched_data *data) __ksym;

extern bool mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;

extern long mptcp_timeout_from_subflow(const struct mptcp_subflow_context *subflow) __ksym;

extern bool mptcp_subflow_stream_memory_free(const struct mptcp_subflow_context *subflow) __ksym;

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

SEC("struct_ops/mptcp_sched_blest_init")
void BPF_PROG(mptcp_sched_blest_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_blest_release")
void BPF_PROG(mptcp_sched_blest_release, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/bpf_blest_data_init")
void BPF_PROG(bpf_blest_data_init, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
        mptcp_sched_data_set_contexts(msk, data);
}

SEC("struct_ops/bpf_blest_get_subflowmm")
int BPF_PROG(bpf_blest_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
	struct mptcp_subflow_context *subflow;
	u64 min_linger_time = ~(u64)0;
	struct sock *sk = (struct sock *)msk;
	u32 pace, burst, wmem;
	int i, choose_idx = 0;
	struct sock *ssk;
	u64 linger_time;
	long tout = 0;


        for (i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
                if (data->contexts[i] == NULL) {
                        break;
                }
                subflow = data->contexts[i];
                ssk = subflow->tcp_sock;
                tout = max(tout, mptcp_timeout_from_subflow(subflow));
                pace = subflow->avg_pacing_rate;
		if (!pace) {
			/* init pacing rate from socket */
			subflow->avg_pacing_rate = __READ_ONCE(ssk->sk_pacing_rate);
			pace = subflow->avg_pacing_rate;
			if (!pace)
				continue;
		}

		linger_time = div_u64((u64)__READ_ONCE(ssk->sk_wmem_queued) << 32, pace);
		if (linger_time == 0) {
			continue;
		}
		if (linger_time < min_linger_time) {
			min_linger_time = linger_time;
			choose_idx = i;
		}	
        }
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
	//bpf_printk("debug: wem %lu, blest burst: %lu, min_lingertime: %llu, choose_idx: %d, tout : %lu", wmem, burst, min_linger_time, choose_idx, tout);
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
struct mptcp_sched_ops blest = {
	.init		= (void *)mptcp_sched_blest_init,
	.release	= (void *)mptcp_sched_blest_release,
	.data_init	= (void *)bpf_blest_data_init,
	.get_subflow	= (void *)bpf_blest_get_subflow,
	.name		= "bpf_blest",
};