from common import *
import os 
from bpf_tools import *
from utils import *
from socket import if_nametoindex
import sys

STOPS_OBJ_PATH = os.path.join(BPF_STOPS_OBJS_PATH, 'bpf_sched_tailcall.c.o')
STOPS_MAP_NAME = "taillcall"

def load_attach_stops():
    with BPFObject(STOPS_OBJ_PATH) as stops_bpf_obj:
        stops_bpf_obj.load()
        map = stops_bpf_obj.get_map(STOPS_MAP_NAME)
        with BPFLink(bpf_map__attach_struct_ops, map) as link: 
            link.disconnect()
        bpf_obj_pin(bpf_map__fd(map), os.path.join("/sys/fs/bpf", STOPS_MAP_NAME))
    print("attach emptcp sched stops success")
    
def clear():
    try: 
        stops_fd = bpf_obj_get(os.path.join("/sys/fs/bpf", STOPS_MAP_NAME))
        key_0 = ct.c_int(0)
        bpf_map_delete_elem(stops_fd, ct.byref(key_0))
    except  Exception as e:
        print(e)
    rm_cmd = "sudo rm /sys/fs/bpf/" + STOPS_MAP_NAME
    os.system(rm_cmd)
        
if __name__ == '__main__':
    try:
        load_attach_stops()
        while True:
            pass
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(e)
    finally:
        clear()