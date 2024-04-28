from common import *
import os 
from bpf_tools import *
from utils import *
import sys


TC_OBJ_PATH = os.path.join(BPF_TC_EGRESS_OBJS_PATH, 'mptcpv0_ctx_entry.c.o')
TC_PROG_NAME = "tc_ctx_entry"

def load_attach_tc():
    dump_all_if_config()
    interfaces = read_if_config()
    with BPFObject(TC_OBJ_PATH) as bpf_obj:
        bpf_obj.load()
        bpf_prog = bpf_obj.get_prog(TC_PROG_NAME)
        with BPFTCEgress(interfaces, bpf_program__fd(bpf_prog)) as tc_links:
            print("attach tc success")
      
def clear():
    interfaces = read_if_config()
    for interface in interfaces:
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