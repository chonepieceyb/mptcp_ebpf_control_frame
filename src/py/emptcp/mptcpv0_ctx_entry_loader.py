from common import *
import os 
from bpf_tools import *
from utils import *
import sys

interfaces = ["enp7s0", "enp8s0", "enp9s0"]

TC_OBJ_PATH = os.path.join(BPF_TC_EGRESS_OBJS_PATH, 'mptcpv0_ctx_entry.c.o')
TC_PROG_NAME = "tc_ctx_entry"
XDP_ENTRY_OBJ_PATH = os.path.join(BPF_XDP_OBJS_PATH, 'mptcpv0_ctx_entry.c.o')
XDP_ENTRY_PROG_NAME = "xdp_ctx_entry"

XDP_IDX0_OBJ_PATH = os.path.join(BPF_XDP_OBJS_PATH, 'parse_mptcp_ts.c.o')
XDP_IDX0_PROG_NAME = "parse_mptcp_ts"

def load_attach_tc():
    #dump_all_if_config()
    #interfaces = read_if_config()
    with BPFObject(TC_OBJ_PATH) as bpf_obj:
        bpf_obj.load()
        bpf_prog = bpf_obj.get_prog(TC_PROG_NAME)
        with BPFTCEgress(interfaces, bpf_program__fd(bpf_prog)) as tc_links:
            print("attach tc success")

def load_attach_xdp():
    #dump_all_if_config()
    #interfaces = read_if_config()
    with BPFObject(XDP_ENTRY_OBJ_PATH) as xdp_entry, \
         BPFObject(XDP_IDX0_OBJ_PATH) as idx0_obj:
        xdp_entry.load()
        idx0_obj.load()
        prog_array =  BPFMap(xdp_entry.get_map("xdp_actions_new"), ct.c_int, ct.c_int)
        #set chain 
        prog_array.update(ct.c_int(0), ct.c_int(bpf_program__fd(idx0_obj.get_prog(XDP_IDX0_PROG_NAME))), 0)
        #attach entry
        for interface in interfaces:
            bpf_xdp_attach(if_nametoindex(interface), bpf_program__fd(xdp_entry.get_prog(XDP_ENTRY_PROG_NAME)), XDP_FLAGS.XDP_FLAGS_UPDATE_IF_NOEXIST)
    print("attach emptcp xdps ctx entry success")

def load_all():
    try:
        load_attach_tc()
        load_attach_xdp()
    except Exception as e:
        print(e)
        clear()

def clear():
    #interfaces = read_if_config()
    for interface in interfaces:
        print("dettach tc eBPF on %d", interface)
        BPFTCEgress.destory_egress_hook(if_nametoindex(interface))
        try:
            print("dettach xdp eBPF on %d", interface)
            bpf_xdp_detach(if_nametoindex(interface), 0)
        except Exception as e:
            print(e)

if __name__ == '__main__':
    if len(sys.argv) != 2: 
        print("usage: ./loader cmd")
        exit(0)
    if sys.argv[1] == 'clear':
        clear()
    elif sys.argv[1] == 'xdp':
        load_attach_xdp()
    elif sys.argv[1] == 'tc':
        load_attach_tc()
    elif sys.argv[1] == 'all':
        load_all()
    else:
        print("usage: ./loader cmd")