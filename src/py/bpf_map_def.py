#-*- coding:utf-8 -*-

from genericpath import exists
from libbpf import BPF_PROG_TYPE
from common import *
from config import CONFIG
import os 
from enum import IntEnum, unique
from bpf_loader import *

#data struct 
@unique 
class Direction(IntEnum):
    INGRESS = 0,
    EGRESS = 1

#some path 
XDP_ACTIONS = "xdp_actions"
XDP_ACTIONS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_ACTIONS)
SUBFLOW_ACTION_INGRESS = "subflow_action_ingress"
SUBFLOW_ACTION_INGRESS_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, SUBFLOW_ACTION_INGRESS)
XDP_ACTIONS_FLAG = "xdp_actions_flag"
XDP_ACTIONS_FLAG_PATH = os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, XDP_ACTIONS_FLAG)

XDP_MAIN = {
    "src_path" : os.path.join(XDP_PROG_PATH, "xdp_main.c"),
    "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "xdp_main.c.o"),
    "progs" : {
        "xdp_main" : {
            "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
        }
    },
    "pin_maps" : {
        XDP_ACTIONS : {
            "pin_path" : XDP_ACTIONS_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        },
        SUBFLOW_ACTION_INGRESS: {
            "pin_path" : SUBFLOW_ACTION_INGRESS_PATH,
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        },
        XDP_ACTIONS_FLAG: {
            "pin_path" : XDP_ACTIONS_FLAG_PATH,
            "flag": BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
        }
    },
    "kw": {
        "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
    }
}

XDP_TAIL_CALL_LIST = [
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "set_recv_win_ingress.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "set_recv_win_ingress.c.o"),
        "progs" : {
            "set_recv_win_ingress" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "set_recv_win_ingress" : 1
        }
    },
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "set_flow_priority_ingress.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "set_flow_priority_ingress.c.o"),
        "progs" : {
            "set_flow_priority_ingress" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            },
            XDP_ACTIONS_FLAG: {
                "pin_path" : XDP_ACTIONS_FLAG_PATH,
                "flag": BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "set_flow_priority_ingress" : 2
        }
    },
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "rm_add_addr_ingress.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "rm_add_addr_ingress.c.o"),
        "progs" : {
            "rm_add_addr_ingress" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
            }
        },
        "pin_maps" : {
            XDP_ACTIONS : {
                "pin_path" : XDP_ACTIONS_PATH,
                "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
            }
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g"]
        },
        "tail_call_map" : {
            "rm_add_addr_ingress" : 3
        }
    }
]

XDP_TAILCALL_NAME_IDX_MAP = get_name_idx_map(XDP_TAIL_CALL_LIST)
XDP_TAILCALL_IDX_NAME_MAP = get_idx_name_map(XDP_TAIL_CALL_LIST)

XDP_ACTION_META_MAP = {
    "1" : False,   #set_recv_win_ingress
    "2" : False,    # set_flow_priority_ingress
    "3" : False,    # set_flow_priority_ingress
} 

def need_meta(action):
    return XDP_ACTION_META_MAP[str(action)]

# test program 
if __name__ == '__main__': 
    loader = BPFObjectLoader
    clear_only_fail = True
    with load(XDP_MAIN, loader, unpin_only_fail=clear_only_fail) as xdp_main:
        prog_array_fd = xdp_main.get_map_fd(XDP_ACTIONS)
        with TailCallLoader(prog_array_fd, XDP_TAIL_CALL_LIST, loader, clear_only_fail=clear_only_fail) as tl:
            pass 


    
    