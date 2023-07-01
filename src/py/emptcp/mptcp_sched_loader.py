from common import *
import os 
from bpf_tools import *
from utils import *
from socket import if_nametoindex
import sys


KPROBE_OBJ_PATH = os.path.join(BPF_KPROBE_OBJS_PATH, 'mptcp_sched_events_monitor.c.o')
KPROBE_PROG_NAME = 'mptcp_event_monitor'
KPROBE_HOOK = 'mptcp_event'

STOPS_OBJ_PATH = os.path.join(BPF_STOPS_OBJS_PATH, 'emptcp_sched_v2.c.o')
STOPS_MAP_NAME= "emptcp_sc"

XDP_OBJ_PATH = os.path.join(BPF_XDP_OBJS_PATH, 'sched_actor_rr.c.o')
XDP_PROG_NAME = "sched_actor"

def load_attach_kprobe(pinned = False):
    with BPFObject(KPROBE_OBJ_PATH) as bpf_obj:
        bpf_obj.load()
        bpf_prog = bpf_obj.get_prog(KPROBE_PROG_NAME)
        with BPFLink(bpf_program__attach_kprobe, bpf_prog, False, KPROBE_HOOK) as link: 
            if pinned:
                link.pin("/sys/fs/bpf/mptcp_monitor_link")
                link.disconnect()
            else:
                link.disconnect()
                try:
                    while True:
                        pass
                except KeyboardInterrupt:
                    pass
    print("attach emptcp sched kprobes success")

def load_attach_stops():
    with BPFObject(STOPS_OBJ_PATH) as stops_bpf_obj:
        stops_bpf_obj.load()
        map = stops_bpf_obj.get_map(STOPS_MAP_NAME)
        with BPFLink(bpf_map__attach_struct_ops, map) as link: 
            link.disconnect()
        bpf_obj_pin(bpf_map__fd(map), os.path.join("/sys/fs/bpf", STOPS_MAP_NAME))
    print("attach emptcp sched stops success")
    
def clear():
    #clear xdps
    dump_all_if_config()
    interfaces = read_if_config()
    for interface in interfaces:
        print("remove xdp of %s", interface)
        try:
            bpf_xdp_detach(if_nametoindex(interface), 0)
        except Exception as e:
            print(e)
    #clear stops
    try: 
        stops_fd = bpf_obj_get(os.path.join("/sys/fs/bpf", STOPS_MAP_NAME))
        key_0 = ct.c_int(0)
        bpf_map_delete_elem(stops_fd, ct.byref(key_0))
    except  Exception as e:
        print(e)
    
    #clear kprobes links and pinned maps
    rm_cmd1 = "sudo rm /sys/fs/bpf/mptcp_conns"
    rm_cmd2 = "sudo rm /sys/fs/bpf/mptcp_key_mapping"
    rm_cmd3 = "sudo rm /sys/fs/bpf/mptcp_monitor_link"
    rm_cmd4 = "sudo rm /sys/fs/bpf/mptcp_sched_flags"
    rm_cmd5 = "sudo rm /sys/fs/bpf/mptcp_sched_policies"
    rm_cmd6 = "sudo rm /sys/fs/bpf/" + STOPS_MAP_NAME
    os.system(rm_cmd1)
    os.system(rm_cmd2)
    os.system(rm_cmd3)
    os.system(rm_cmd4)
    os.system(rm_cmd5)
    os.system(rm_cmd6)
    dump_all_if_config()
    
def load_attach_xdps():
    dump_all_if_config()
    interfaces = read_if_config()
    with BPFObject(XDP_OBJ_PATH) as bpf_obj:
        bpf_obj.load()
        bpf_prog = bpf_obj.get_prog(XDP_PROG_NAME)

        for interface in interfaces:
            bpf_xdp_attach(if_nametoindex(interface), bpf_program__fd(bpf_prog), XDP_FLAGS.XDP_FLAGS_UPDATE_IF_NOEXIST)
    print("attach emptcp sched xdps success")
            
def attach_all():
    try:
        load_attach_kprobe(True)
        load_attach_xdps()
        load_attach_stops()
    except Exception as e:
        print(e)
        clear()

if __name__ == '__main__':
    if len(sys.argv) != 2: 
        print("usage: ./loader cmd")
        exit(0)
        
    if sys.argv[1] == 'clear':
        clear()
    elif sys.argv[1] == 'all':
        attach_all()
    elif sys.argv[1] == 'kprobe':
        load_attach_kprobe(False)
    else:
        print("usage: ./loader cmd")
   
    