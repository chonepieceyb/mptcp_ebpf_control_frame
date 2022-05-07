#-*- coding:utf-8 -*-
import ctypes as ct
from common import *
from enum import IntEnum , unique
from config import CONFIG

@unique 
class selector_op_type_t(IntEnum):
    SELECTOR_AND = 0,
    SELECTOR_OR = 1

selector_op_2_str = {
    str(selector_op_type_t.SELECTOR_AND) : "AND", 
    str(selector_op_type_t.SELECTOR_OR) : "OR", 
}

@unique 
class param_type_t(IntEnum):
    IMME = 0,
    MEM = 1

#network bytes order 
class tcp4tuple(ct.Structure):
    _fields_  = [\
        ("local_port", ct.c_uint16),\
        ("remote_port", ct.c_uint16),\
        ("local_addr", ct.c_uint32),\
        ("remote_addr", ct.c_uint32)
    ]

class tcp2tuple(ct.Structure):
    _fields_  = [\
        ("local_addr", ct.c_uint32),\
        ("remote_addr", ct.c_uint32)\
    ]


class chain_t(ct.Union):
    _fields_  = [\
        ("idx", ct.c_uint8),\
        ("next_idx", ct.c_uint8),\
    ]

class selector_t(ct.Structure):
    _fields_  = [\
        ("chain", chain_t),\
        ("op", ct.c_uint8),\
        ("rsv", ct.c_uint16),\
    ]

class selector_chain_t(ct.Structure):
    _fields_  = [\
        ("selectors", selector_t * CONFIG.max_policy_len)
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

class action_t(ct.Structure):
    _fields_  = [\
        ("chain", chain_t),\
        ("param_type", ct.c_uint8, 2),\
        ("rsv", ct.c_uint8, 6),\
        ("param", param_union)
    ]

class action_chain_t(ct.Structure):
    _fields_  = [\
        ("actions", action_t * CONFIG.max_policy_len),
        ("ref_cnt", ct.c_uint32)
    ]

class flow_prio_param_t(ct.Structure): 
    _fields_  = [\
        ("B", ct.c_uint8, 1),\
        ("A", ct.c_uint8, 1),\
        ("rsv", ct.c_uint8, 6),\
        ("address_id", ct.c_uint8)
    ]

action_chain_id_t = ct.c_uint64

class default_action_t(ct.Structure):
    _fields_  = [\
        ("id", action_chain_id_t),\
        ("enable", ct.c_int)
    ]

class perf_event_header_t(ct.Structure):
    _fields_  = [\
        ("time_ns", ct.c_uint64),\
        ("event", ct.c_uint16),\
        ("len", ct.c_uint16)
    ]

eMPTCP_event_header_t = perf_event_header_t

class fin_event_t(ct.Structure):
    _fields_  = [\
        ("header", eMPTCP_event_header_t),\
        ("flow", tcp4tuple)
    ]

class mp_capable_event_t(ct.Structure):
    _fields_  = [\
        ("header", eMPTCP_event_header_t),\
        ("flow", tcp4tuple),\
        ("local_key", ct.c_uint64), \
        ("remote_key", ct.c_uint64)
    ]

class mp_join_event_t(ct.Structure):
    _fields_  = [\
        ("header", eMPTCP_event_header_t),\
        ("flow", tcp4tuple),\
        ("token", ct.c_uint32)
    ]

if __name__ == '__main__':
    print(ct.sizeof(flow_prio_param_t))