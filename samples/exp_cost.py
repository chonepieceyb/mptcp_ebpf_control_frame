import os 
import sys

PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PROJECT_PATH,"./src/py/emptcp"))
import ctypes as ct
import os
from bpf_loader import *
from bpf_map_def import *
import statistics

DEBUG_EVENTS_PATH =  "/sys/fs/bpf/eMPTCP/debug_events"

event_name_dict = {
    1 : "set_recv_win",
    2 : "set_flow_prio",
    3 : "rm_add_addr",
    5 : "tcp2sel",
    6  : "tcp4sel",
    7 : "tcpsel",
    8 : "sel_entry",
    9 : "action_entry"
}

'''
    {
        1 : 
        2 :
        3 : 
    }
'''
EVENT_DICT  = {} 

class debug_time_event_t(ct.Structure): 
    _fields_  = [\
        ("event", ct.c_int),\
        ("start", ct.c_uint64),\
        ("end", ct.c_uint64)
    ]

ALL_COUNT = 0

def debug_event_cb(ctx, cpu,  data, size):
    global ALL_COUNT
    if size < ct.sizeof(debug_time_event_t):
        return 
    e = ct.cast(data, ct.POINTER(debug_time_event_t)).contents
    event = e.event
    if event not in EVENT_DICT:
        el = EVENT_DICT[event] = []
    else: 
        el = EVENT_DICT[event]
    el.append(e.end - e.start)
    ALL_COUNT += 1

def process_event_dict():
    all = 0
    for event, list in EVENT_DICT.items():
        all = all + sum(list) / 1000000000
        print("%s %f %d"%(event_name_dict[event], statistics.mean(list), len(list)))
    print ("all: %f"%all) 

if __name__ == '__main__':
    import os
    import sys 


    debug_events_fd = bpf_obj_get(DEBUG_EVENTS_PATH)
    
    print("tracing")
    with PerfBuffer(debug_events_fd, debug_event_cb) as pb:
        while True:
            try:
                pb.poll(timeout_ms = 10)
            except KeyboardInterrupt:
                break
    process_event_dict()
    print("all count: %d"%ALL_COUNT)
