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


def debug_event_cb(ctx, cpu,  data, size):
    if size < ct.sizeof(debug_time_event_t):
        return 
    e = ct.cast(data, ct.POINTER(debug_time_event_t)).contents
    event = e.event
    if event not in EVENT_DICT:
        el = EVENT_DICT[event] = []
    else: 
        el = EVENT_DICT[event]
    el.append(e.end - e.start)

def process_event_dict():
    for event, list in EVENT_DICT.items():
        print("%s %f"%(event_name_dict[event], statistics.mean(list)))

if __name__ == '__main__':
    xdp_set_debug()
    loader = BPFObjectLoader
    clear_only_fail = True
    with load(XDP_SELECTOR_ENTRY, loader, unpin_only_fail=clear_only_fail) as xdp_selector_entry, \
      load(XDP_ACTION_ENTRY, loader, unpin_only_fail=clear_only_fail) as xdp_action_entry: 
      xdp_selectors_fd = xdp_selector_entry.get_map_fd(XDP_SELECTORS)
      xdp_actions_fd = xdp_action_entry.get_map_fd(XDP_ACTIONS)
      action_entry_idx = ct.c_int(ACTION_ENTRY_IDX)
      action_entry_fd = ct.c_int(xdp_action_entry.get_prog_fd("action_entry"))
      bpf_map_update_elem( xdp_actions_fd, ct.byref(action_entry_idx), ct.byref(action_entry_fd))
      with TailCallLoader(xdp_selectors_fd, XDP_SELECTORS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as stl,\
          TailCallLoader(xdp_actions_fd, XDP_ACTIONS_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as atl:
            debug_events_fd = bpf_obj_get(DEBUG_EVENTS_PATH)
            with PerfBuffer(debug_events_fd, debug_event_cb) as pb:
                while True:
                    try:
                        pb.poll(timeout_ms = 10)
                    except KeyboardInterrupt:
                        break
            print(EVENT_DICT)
            process_event_dict()