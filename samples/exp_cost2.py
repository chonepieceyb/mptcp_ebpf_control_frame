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
    6 : "tcp4sel",
    7 : "tcpsel",
    8 : "sel_entry",
    9 : "action_entry"
}

mean_cost = {
    1 : 283.348890,
    2 : 586.554042,
    3 : 414.862246,
    5 : 473.882506,
    6 : 525.415689,
    7 : 349.788852,
    8 : 414.924469,
    9 : 542.459426
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

FILE = None 

def debug_event_cb(ctx, cpu,  data, size):
    if size < ct.sizeof(debug_time_event_t):
        return 
    e = ct.cast(data, ct.POINTER(debug_time_event_t)).contents
    FILE.write("%d %d %d\n"%(e.event, e.start, e.end))
    '''
        if event not in EVENT_DICT:
            el = EVENT_DICT[event] = []
        else: 
            el = EVENT_DICT[event]
        el.append(e.end - e.start)
    '''
ALL_COUNT = 0
BAD_COUNT = 0

def read_out(file_output_name):
    global BAD_COUNT
    global ALL_COUNT
    with open(file_output_name, 'r') as f:
        lines = f.readlines()
        for line in lines: 
            item = line.strip().split()
            event = int(item[0])
            start = int(item[1])
            end = int(item[2])
            ALL_COUNT += 1
            if event not in EVENT_DICT:
                el = EVENT_DICT[event] = []
            else: 
                el = EVENT_DICT[event]
            if (end - start < 15000) : 
                el.append(max(0, end - start-7519))
            else: 
                el.append(mean_cost[event])
                BAD_COUNT += 1

def process_event_dict():
    all = 0
    for event, list in EVENT_DICT.items():
        all = all + sum(list) / 1000000000
        print("%s %f"%(event_name_dict[event], statistics.mean(list)))
    print ("all: %f"%all) 

if __name__ == '__main__':
    import os
    import sys 

    exp_name = sys.argv[1]
    file_output_name = "cost_%s.out"%exp_name 

    debug_events_fd = bpf_obj_get(DEBUG_EVENTS_PATH)
    
    with open(file_output_name, 'w') as f : 
        FILE = f 
        print("tracing")
        with PerfBuffer(debug_events_fd, debug_event_cb) as pb:
            while True:
                try:
                    pb.poll(timeout_ms = 10)
                except KeyboardInterrupt:
                    break
    read_out(file_output_name)
    process_event_dict()
    print("all count", ALL_COUNT)
    print("bad count", BAD_COUNT)