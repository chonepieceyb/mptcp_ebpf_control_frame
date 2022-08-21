#-*- coding:utf-8 -*-
from bcc import BPF
from socket import htons, htonl
import ctypes as ct 

ip2int = lambda ip: sum([256 ** j * int(i) for j, i in enumerate(ip.split('.')[::-1])])

def local_addr_filter(local_addr):
    local_net = htonl(ip2int(local_addr))
    return "(sk->sk_rcv_saddr==%d)"%local_net 

def remote_addr_filter(remote_addr):
    remote_addr = htonl(ip2int(remote_addr))
    return "(sk->sk_daddr==%d)"%remote_addr 

def local_port_filter(local_port):
    local_port = htons(local_port)
    return "(sk->sk_num==%d)"%local_port 

def remote_port_filter(remote_port):
    remote_port = htons(remote_port)
    return "(sk->sk_dport==%d)"%remote_port 

def filter_and(*args):
    return "(%s)"%(' && '.join(args))

def filter_or(*args):
    return "(%s)"%(' || '.join(args))

def generate_filter(*args):
    #first one 
    if len(args) == 0 :
        return "__target = 0;"

    filter_exp = '''
if (%s) {
    __target = %d;
}'''%(args[0][0], args[0][1])

    for filter in args[1:]: 
        next_exp = '''
else if (%s) {
    __target = %d;
}'''%(filter[0], filter[1])
        filter_exp += next_exp

    filter_exp += '''
else {
    __target = -1;
}'''
    return filter_exp 

bpf_program = '''
#include <net/sock.h>
#include <net/tcp.h> 

struct tcp_rcv_event_t {
    __u64 timestamp_ns; 
    int sk_sndbuf;
    int sk_wmem_queued;
    __u64 bytes_sent;
    __u64 bytes_acked;
    __u32 snd_ssthresh;
    __u32 snd_cwnd;
    __u32 snd_wnd;
    //__u32 rcv_wnd;
    int target; 
};

BPF_PERF_OUTPUT(tcp_rcv_events);


int kprobe__tcp_rcv_established(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    struct tcp_sock * __tcpsock = (struct tcp_sock *)sk;
    int __target;

    __u32 family = sk->sk_family;
    if (family != AF_INET) return 0;   //only support ipv4 now 
    FILTER

    if (__target < 0) return 0;  //not our target 
    
    struct tcp_rcv_event_t __event;
    __builtin_memset(&__event, 0, sizeof(struct tcp_rcv_event_t));
    
    __event.timestamp_ns = bpf_ktime_get_ns();
    __event.target = __target;
    __event.sk_sndbuf = sk->sk_sndbuf;
    __event.sk_wmem_queued = sk->sk_wmem_queued;
    __event.bytes_sent = __tcpsock->bytes_sent ;
    __event.bytes_acked = __tcpsock->bytes_acked;
    __event.snd_ssthresh = __tcpsock->snd_ssthresh;
    __event.snd_cwnd = __tcpsock->snd_cwnd;
    __event.snd_wnd = __tcpsock->snd_wnd;
    //__event.rcv_wnd = __tcpsock->rcv_wnd;

    tcp_rcv_events.perf_submit(ctx, &__event, sizeof(__event));
    return 0;
}

'''


"""
struct tcp_rcv_event_t {
    __u64 timestamp_ns; 
    int sk_sndbuf;
    int sk_wmem_queued;
    __u64 bytes_sent;
    __u32 snd_ssthresh;
    __u32 snd_cwnd;
    __u32 snd_wnd;
    //__u32 rcv_wnd;
    int target; 
};
"""

files = {
}

class tcp_rcv_event_t(ct.Structure):
    _fields_  = [\
        ("timestamp_ns", ct.c_uint64),\
        ("sk_sndbuf", ct.c_int),\
        ("sk_wmem_queued", ct.c_int),\
        ("bytes_sent", ct.c_uint64),\
        ("bytes_acked", ct.c_uint64),\
        ("snd_ssthresh", ct.c_uint32),\
        ("snd_cwnd",  ct.c_uint32),\
        ("snd_wnd",  ct.c_uint32),\
        #("rcv_wnd",  ct.c_uint32),\
        ("target",  ct.c_int),\
    ]

def perf_output_callback(cpu, data, size):
    event = ct.cast(data, ct.POINTER(tcp_rcv_event_t)).contents
    line = "%d %d %d %d %d %d %d %d\n"%(event.timestamp_ns, event.sk_sndbuf, event.sk_wmem_queued, event.bytes_sent, event.bytes_acked, event.snd_ssthresh, event.snd_cwnd, event.snd_wnd)
    files[event.target].write(line)

if __name__ == '__main__': 
    import sys
    #test filter 
    sub1 = filter_and(local_addr_filter("172.16.12.128"), remote_addr_filter("172.16.12.131"))
    sub2 = filter_and(local_addr_filter("172.16.12.129"), remote_addr_filter("172.16.12.132"))
    filter_exp = generate_filter((sub1,1), (sub2,2))
    
    bpf_program = bpf_program.replace("FILTER", filter_exp)
    print(bpf_program)
    bpf = BPF(text=bpf_program)
    bpf.attach_kprobe(event = "tcp_rcv_established", fn_name = "kprobe__tcp_rcv_established")

    exp_name = sys.argv[1]

    bpf["tcp_rcv_events"].open_perf_buffer(perf_output_callback)
    header = "timestamp_ns sk_sndbuf sk_wmem_queued bytes_sent bytes_acked snd_ssthresh snd_cwnd snd_wnd\n"
    with open("%s_sub1.txt"%exp_name, "w") as file1, open("%s_sub2.txt"%exp_name, "w") as file2: 
        file1.write(header)
        file2.write(header)
        files[1] = file1 
        files[2] = file2 
        print("start tracing")
        while True:
            try:
                bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()
    
    

