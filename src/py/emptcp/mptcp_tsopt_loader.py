from common import *
import os 
from bpf_tools import *
from utils import *
import sys

interfaces = ["enp7s0", "enp8s0", "enp9s0"]

TC_MPTCP_TS_OBJ_PATH = os.path.join(BPF_TC_EGRESS_OBJS_PATH, 'mptcp_ts_option.c.o')
TC_MPTCP_TS_PROG_NAME = "add_mptcp_ts_option"

def load_attach_tc():
    #dump_all_if_config()
    #interfaces = read_if_config()
    with BPFObject(TC_MPTCP_TS_OBJ_PATH) as mpts_obj:
        mpts_obj.load()
        bpf_prog = mpts_obj.get_prog(TC_MPTCP_TS_PROG_NAME)
        with BPFTCEgress(interfaces, bpf_program__fd(bpf_prog)) as tc_links:
            print("attach tc mptcp ts success")

def clear():
    interfaces = read_if_config()
    for interface in interfaces:
        print("dettach tc eBPF on %d", interface)
        BPFTCEgress.destory_egress_hook(if_nametoindex(interface))

if __name__ == '__main__':
    if len(sys.argv) != 2: 
        print("usage: ./loader cmd")
        exit(0)
    if sys.argv[1] == 'clear':
        clear()
    elif sys.argv[1] == 'tc':
        load_attach_tc()
    else:
        print("usage: ./loader cmd")