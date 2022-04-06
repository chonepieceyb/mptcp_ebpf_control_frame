#-*- coding:utf-8 -*-

from libbpf import BPF_PROG_TYPE
from common import *
from config import CONFIG
import os 
from enum import IntEnum, unique

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

XDP_MAIN = {
    "src_path" : os.path.join(XDP_PROG_PATH, "xdp_main.c"),
    "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "xdp_main.c.o"),
    "progs" : {
        "xdp_main" : {
            "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP
        }
    },
    "pin_maps" : {
        "xdp_actions" : XDP_ACTIONS_PATH,
        "subflow_action_ingress": SUBFLOW_ACTION_INGRESS_PATH
    },
    "kw": {
        "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g", "-O2"]
    }
}

XDP_TAIL_CALL_LIST = [
    {
        "src_path" : os.path.join(XDP_PROG_PATH, "set_recv_win_ingress.c"),
        "obj_path" : os.path.join(BPF_XDP_OBJS_PATH, "set_recv_win_ingress.c.o"),
        "progs" : {
            "set_recv_win_ingress" : {
                "prog_type" : BPF_PROG_TYPE.BPF_PROG_TYPE_XDP,
                "pin_path" : os.path.join(BPF_VFS_PREFIX, CONFIG.progect_pin_prefix, "set_recv_win_ingress")
            }
        },
        "pin_maps" : {
            "xdp_actions" : XDP_ACTIONS_PATH
        },
        "kw": {
            "cflags" : ["-I%s"%SRC_BPF_KERN_PATH, "-g", "-O2"]
        },
        "tail_call_map" : {
            "set_recv_win_ingress" : 1
        }
    }
]

def get_name_idx_map(tail_call_list):
    name_idx_map = {}
    for list_idx, item in enumerate(tail_call_list):
        for name, idx in item["tail_call_map"].items():
            if name in name_idx_map:
                raise RuntimeError("failed to set name_idx_map, tail call name :%s exists"%name)
            val = {
                "tail_call_idx" : int(idx),
                "list_idx": int(list_idx)
            }
            name_idx_map[name] = val
    return name_idx_map

def get_idx_name_map(tail_call_list):
    idx_name_map = {}
    for list_idx, item in  enumerate(tail_call_list):
        for name, idx in item["tail_call_map"].items():
            if str(idx) in idx_name_map:
                raise RuntimeError("failed to set name_idx_map, tail call idx :%d exists"%idx)
            val = {
                "tail_call_name" : name,
                "list_idx" : list_idx
            }
            idx_name_map[str(idx)] = val
    return idx_name_map

XDP_TAILCALL_NAME_IDX_MAP = get_name_idx_map(XDP_TAIL_CALL_LIST)
XDP_TAILCALL_IDX_NAME_MAP = get_idx_name_map(XDP_TAIL_CALL_LIST)


if __name__ == '__main__':
    print(XDP_TAILCALL_NAME_IDX_MAP)
    print(XDP_TAILCALL_IDX_NAME_MAP)