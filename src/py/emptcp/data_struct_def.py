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

class ethhdr(ct.Structure) :
    _pack_ = 1
    _fields_  = [\
        ("h_dest", ct.c_ubyte * 6),\
        ("h_source", ct.c_ubyte * 6),\
        ("h_proto", ct.c_uint16)
    ]

class mp_dss(ct.Structure) :
    _fields_  = [\
        ("kind", ct.c_uint8),\
        ("len", ct.c_uint8),\
        ("rsv1", ct.c_uint16, 4), \
        ("sub", ct.c_uint16, 4), \
        ("A", ct.c_uint16, 1), \
        ("a", ct.c_uint16, 1), \
        ("M", ct.c_uint16, 1), \
        ("m", ct.c_uint16, 1), \
        ("F", ct.c_uint16, 1), \
        ("rsv2", ct.c_uint16, 3), \
    ]
'''
class mptcp_copy_pkt_event_t(ct.Structure):
    _fields_  = [\
        ("header", eMPTCP_event_header_t),\
        ("flow", tcp4tuple),\
        ("eth", ethhdr),\
        ("window", ct.c_uint16),\
        ("seq", ct.c_uint32),\
        ("ack_seq", ct.c_uint32),\
        ("dss_opt", mp_dss),\
        ("dss_ack", ct.c_ubyte * 8)
    ]
'''

class mptcp_copy_pkt_event_t(ct.Structure):
    _fields_  = [\
        ("header", eMPTCP_event_header_t),\
        ("flow", tcp4tuple),\
        ("eth", ethhdr),\
        ("window", ct.c_uint16),\
        ("seq", ct.c_uint32),\
        ("ack_seq", ct.c_uint32),\
        ("ts", ct.c_ubyte * 10)
    ]


class rm_add_addr_event_t(ct.Structure):
    _fields_  = [\
        ("header", eMPTCP_event_header_t),\
        ("flow", tcp4tuple),\
        ("opt_len", ct.c_uint32),\
        ("add_addr_opt", ct.c_ubyte * 18)
    ]

#without addr_id， little end
class mp_prio(ct.Structure): 
    _fields_  = [\
        ("kind", ct.c_uint8),\
        ("len", ct.c_uint8),\
        ("b", ct.c_uint8, 1), \
        ("rsv", ct.c_uint8, 3), \
        ("sub", ct.c_uint8, 4), 
    ]

class metric_param_t(ct.Structure):
    _fields_  = [\
        ("pkt", ct.c_uint8, 1),
        ("flow", ct.c_uint8, 1),
        ("rtt", ct.c_uint8, 1),
        ("rsv1", ct.c_uint8, 5),
        ("rsv2", ct.c_uint8)
    ]

if __name__ == '__main__':
    from utils import *
    import socket
    from scapy.all import Ether, IP, raw, TCP, hexdump

    mac2str = lambda x: ':'.join(["%02x"%b for b in x])

    def build_packet(add_addr_opt_bytes, copy_pkt_event):
        # 先不放 timestamp 选项试一下
        #(30,b'\x10\x07\x53\x20\xda\xef\x45\x73\x96\xf4')
        options = []
        opt_len = 0
        add_addr_opt = (30, add_addr_opt_bytes)
        opt_len = opt_len + 2 + len(add_addr_opt_bytes)   

        dss_bytes = bytearray(copy_pkt_event.dss_opt)[2:]  # without first 2 bytes of kind and len 
        if copy_pkt_event.dss_opt.a :
            #8bytes
            dss_bytes.extend(copy_pkt_event.dss_ack.to_bytes(8, byteorder = "big", signed = False)) #little end?
        else :
            #4bytes
            dss_bytes.extend(copy_pkt_event.dss_ack.to_bytes(4, byteorder = "big", signed = False)) #little end?
        dss_opt = (30, bytes(dss_bytes))
        opt_len = opt_len + len(dss_bytes) + 2

        #nop 
        res_opt_len = (4 - opt_len % 4) 
        for _ in range(0, res_opt_len) : 
            options.append((1,b''))                                                           
        options.append(add_addr_opt)
        options.append(dss_opt)
        
        seq = socket.ntohl(copy_pkt_event.seq)
        ack = socket.ntohl(copy_pkt_event.ack_seq)
        pkt = Ether(dst=mac2str(copy_pkt_event.eth.h_dest), src=mac2str(copy_pkt_event.eth.h_source))/\
            IP(src=int2ip(socket.ntohl(copy_pkt_event.flow.remote_addr)), dst=int2ip(socket.ntohl(copy_pkt_event.flow.local_addr)))/\
            TCP(sport=socket.ntohs(copy_pkt_event.flow.remote_port), dport = socket.ntohs(copy_pkt_event.flow.local_port), flags ='A',seq = seq, ack = ack, options=options)
        return pkt

    copy_pkt_event = mptcp_copy_pkt_event_t()
    setvalue(copy_pkt_event, 0)

    copy_pkt_event.h_proto = socket.htons(2048)
    print(copy_pkt_event.h_proto)
    rm_add_addr_event = rm_add_addr_event_t()
    setvalue(rm_add_addr_event, 0)
    add_addr_opt_bytes = bytearray(rm_add_addr_event.add_addr_opt)[2:]
    pkt = build_packet(bytes(add_addr_opt_bytes), copy_pkt_event)
    pkt.show2()
    print(raw(pkt))
