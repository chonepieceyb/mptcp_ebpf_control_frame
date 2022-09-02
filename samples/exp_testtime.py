#-*- coding:utf-8 -*-
from bcc import BPF
from socket import htons, htonl
import ctypes as ct 
import statistics

bpf_program = '''
#include <net/sock.h>
#include <net/tcp.h> 

struct time_event_t {
    __u64 start;
    __u64 end;
};

BPF_PERF_OUTPUT(events);

int kprobe__tcp_rcv_established(struct pt_regs *ctx) {
    struct time_event_t __event;
    __event.start = bpf_ktime_get_ns();
    __event.end = bpf_ktime_get_ns();
    events.perf_submit(ctx, &__event, sizeof(__event));
    return 0;
}

'''
class tcp_rcv_event_t(ct.Structure):
    _fields_  = [\
        ("start", ct.c_uint64),\
        ("end", ct.c_uint64)
    ]

LIST = []

def perf_output_callback(cpu, data, size):
    event = ct.cast(data, ct.POINTER(tcp_rcv_event_t)).contents
    print(event.end - event.start)
    if (event.end - event.start < 15000) : 
        LIST.append(event.end - event.start)

if __name__ == '__main__': 
    bpf = BPF(text=bpf_program)
    bpf.attach_kprobe(event = "tcp_rcv_established", fn_name = "kprobe__tcp_rcv_established")


    bpf["events"].open_perf_buffer(perf_output_callback)
   
    while True:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            break 

    print(len(LIST), statistics.mean(LIST))