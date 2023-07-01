from common import *
import os 
from bpf_tools import *
from utils import *
from socket import if_nametoindex, htonl, htons
import sys
import time

CREDITS_GEN_RATE = ct.c_int64(360)
CREDIT_GEN_DUR = 10    #ms

CREDIT_MAP_NAME = "credits_map"

DADDR_LIST = [htonl(3232266798), htonl(3232266822)]

class credit_key(ct.Structure):
    _fields_  = [\
        ("daddr", ct.c_uint32),\
    ]

def gen_credits(map_fd, daddr):
    ckey = credit_key()
    ckey.daddr = daddr
    bpf_map_update_elem(map_fd, ct.byref(ckey), ct.byref(CREDITS_GEN_RATE), 0)
   
    
if __name__ == '__main__':
    try:
        map_fd = bpf_obj_get(os.path.join("/sys/fs/bpf", CREDIT_MAP_NAME))
        while True:
            for daddr in DADDR_LIST:
                    gen_credits(map_fd, daddr)
            time.sleep(CREDIT_GEN_DUR/1000)
    except KeyboardInterrupt:
        pass 
    except Exception as e:
        print(e)