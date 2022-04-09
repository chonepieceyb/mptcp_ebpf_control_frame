#-*- coding:utf-8 -*-
import ctypes as ct
from common import *
from enum import IntEnum , unique
from config import CONFIG

@unique 
class param_type_t(IntEnum):
    IMME = 0,
    MEM = 1

#network bytes order 
class tcp_4_tuple(ct.Structure):
    _fields_  = [\
        ("local_addr", ct.c_uint32),\
        ("peer_addr", ct.c_uint32),\
        ("local_port", ct.c_uint16),\
        ("peer_port", ct.c_uint16)\
    ]

class tcp_2_tuple(ct.Structure):
    _fields_  = [\
        ("local_addr", ct.c_uint32),\
        ("peer_addr", ct.c_uint32)\
    ]

flow_key_t = tcp_2_tuple

class action_union(ct.Union):
    _fields_  = [\
        ("action", ct.c_uint8),\
        ("next_action", ct.c_uint8),\
    ]

class mem_param(ct.Structure):
    _fields_  = [\
        ("offset", ct.c_uint8),\
        ("version", ct.c_uint8),\
    ]

class param_union(ct.Union):
    _fields_  = [\
        ("imme", ct.c_uint16),
        ("mem", mem_param)
    ]

class action(ct.Structure):
    _fields_  = [\
        ("param_type", ct.c_uint8, 2),\
        ("index", ct.c_uint8, 2),\
        ("version", ct.c_uint8, 4),\
        ("u1", action_union),\
        ("u2", param_union)
    ]

class subflow_xdp_actions(ct.Structure):
    _fields_  = [\
        ("version", ct.c_uint8),\
        ("actions", action * CONFIG.subflow_max_action_num),\
        ("params", ct.c_byte * CONFIG.subflow_param_bytes)
    ]

class flow_prio_param_t(ct.Structure): 
    _fields_  = [\
        ("B", ct.c_uint8, 1),\
        ("A", ct.c_uint8, 1),\
        ("rsv", ct.c_uint8, 6),\
        ("address_id", ct.c_uint8)
    ]

xdp_action_value_t = subflow_xdp_actions

if __name__ == '__main__':
    print(ct.sizeof(flow_prio_param_t))