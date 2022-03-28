#-*- coding:utf-8 -*-
import ctypes as ct
from xml.dom.minidom import TypeInfo 
from config import CONFIG
from enum import IntEnum

token_type = ct.c_uint32
mptcp_key_type = ct.c_uint64

class direction(IntEnum):
    CLIENT = 0,
    SERVER = 1

#network bytes order 
class tcp_4_tuple(ct.Structure):
    _fields_  = [\
        ("local_addr", ct.c_uint32),\
        ("peer_addr", ct.c_uint32),\
        ("local_port", ct.c_uint16),\
        ("peer_port", ct.c_uint16)\
    ]

#network bytes order 
#暂时考虑只有一个方向, 只有采用编译的手段加进去
class mp_capable_event_t(ct.Structure):
    _fields_ = [\
        ("connect", tcp_4_tuple),\
        ("sended_data", ct.c_uint32),\
        ("peer_key", mptcp_key_type)\
    ]

'''
    flow_nums: 当前建立的子流数
    sub_flows: 子流的信息
'''
class mptcp_connect(ct.Structure):
    _fields_ = [\
        ("flow_nums", ct.c_uint32),\
        ("subflows", tcp_4_tuple * CONFIG.mptcp_connects.max_subflow_entries)
    ]

MAIN_FLOW_ID =  -1

'''
int8 address_id :  subflow的 address_id , 如果 address_id 为 -1 代表是主流 ,
int8 direction :  代表方向
int16 action 该子流采用的动作
u32 token 子流对应的mptcp 主流的 token 
u32 client_iseq 本机发送的 init seq 
u32 server_iseq 对端发送的 init seq 
u32 client_pkts 目前发送的数据包数
u32 server_pkts 目前收到的数据包数
u64 sended_data 目前发送的数据数（计算方式是，每收到一个包就加上这个包的负载长度，可能存在误差，因为收到的pkt可能损坏了） 
u64 recved_data 目前收到的数据数计算方式同上
总大小为 40byte
'''
class subflow(ct.Structure):
    _fields_ = [\
        ("address_id", ct.c_int8),\
        ("direction", ct.c_int8),\
        ("action", ct.c_int16),\
        ("token", ct.c_uint32),\
        ("sended_pkts", ct.c_uint32),\
        ("recved_pkts", ct.c_uint32),\
        ("sended_data", ct.c_uint64),\
        ("recved_data", ct.c_uint64)
    ]


if __name__ == '__main__' :
    print(ct.sizeof(mp_capable_event_t))
