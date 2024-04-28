from common import *
import os 
from bpf_tools import *
from utils import *
from socket import if_nametoindex
import sys
import time

KPROBE_OBJ_PATH = os.path.join(BPF_KPROBE_OBJS_PATH, 'mptcp_pm_events_monitor_v0.c.o')
KPROBE_PROG_HOOKS = [('full_mesh_new_session_handler', 'full_mesh_new_session'), \
    ('tcp_set_state_handler', 'tcp_set_state'), 
]

def load_attach_kprobe():
    with BPFObject(KPROBE_OBJ_PATH) as bpf_obj:
        bpf_obj.load()
        for prog_hook in KPROBE_PROG_HOOKS:
            bpf_prog = bpf_obj.get_prog(prog_hook[0])
            link = bpf_program__attach_kprobe(bpf_prog, False, prog_hook[1])
            bpf_link__disconnect(link)
            #V0 kernel is too old to use bpf_link__pin
    print("attach mptcp v0 kprobes success")
    try:
        while True:
            time.sleep(60)
            pass
    except KeyboardInterrupt:
        pass
    
def clear():
    #clear kprobes links and pinned mapsmptcp_token_key_map
    rm_cmd1 = "rm /sys/fs/bpf/mptcp_subflow_key_map"
    rm_cmd2 = "rm /sys/fs/bpf/mapsmptcp_token_key_map"
    rm_cmd3 = "rm /sys/fs/bpf/emptcp_ctx_map"
    os.system(rm_cmd1)
    os.system(rm_cmd2)
    os.system(rm_cmd3)
    #kprobes 
    for prog_hook in KPROBE_PROG_HOOKS:
        rm_cmd = "rm /sys/fs/bpf/kprobe_%s"%prog_hook[0]
        os.system(rm_cmd)
    
if __name__ == '__main__':
    if len(sys.argv) != 2: 
        print("usage: ./loader cmd")
        exit(0)
        
    if sys.argv[1] == 'clear':
        clear()
    elif sys.argv[1] == 'kprobe':
        load_attach_kprobe()
    else:
        print("usage: ./loader cmd")
   