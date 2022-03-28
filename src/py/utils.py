#-*- coding:utf-8 -*-
from genericpath import exists
import hashlib
import os 
from config import CONFIG
import ctypes as ct 
from libbpf import *
from data_struct_def import *
from common import CONFIG_PATH

IF_CONF_PATH = os.path.join(CONFIG_PATH, CONFIG.if_config_path)

def dump_if_config(interfaces) : 
    with open(IF_CONF_PATH, 'w') as f: 
        for interface in interfaces: 
            f.write(interface + '\n')

def dump_all_if_config() : 
    cmd = "ls -l /sys/class/net/ | grep -v virtual | sed '1d' | awk 'BEGIN {FS=\"/\"} {print $NF}' > %s"%(IF_CONF_PATH)
    os.system(cmd)

def read_if_config():
    interfaces  = []
    with open(IF_CONF_PATH, 'r') as f: 
        lines =  f.readlines()
        for line in lines : 
            line = line.strip()
            if line != "" :
                interfaces.append(line)
    return interfaces

#bpf_map_path
MPTCP_OUTPUT_PATH = os.path.join(CONFIG.bpf_virtual_fs_path, CONFIG.tc_pin_prefix, CONFIG.mp_capable_perf_output.name)
MPTCP_CONNECTS_PATH = os.path.join(CONFIG.bpf_virtual_fs_path, CONFIG.tc_pin_prefix, CONFIG.mptcp_connects.name)
SUBFLOWS_PATH = os.path.join(CONFIG.bpf_virtual_fs_path, CONFIG.tc_pin_prefix, CONFIG.subflows.name)

#暂时不用配置了
TC_EGRESS_TAILCALL_PATH = os.path.join(CONFIG.bpf_virtual_fs_path, CONFIG.tc_pin_prefix, "tc_egress_tailcall")
TC_EGRESSS_MPCAPABLE_PATH = os.path.join(CONFIG.bpf_virtual_fs_path, CONFIG.tc_pin_prefix, "tc_egress_mpcapable")
TC_EGRESSS_JOIN_PATH = os.path.join(CONFIG.bpf_virtual_fs_path, CONFIG.tc_pin_prefix, "tc_egress_join")

def pin_mptcp_output():
    if not os.path.exists(MPTCP_OUTPUT_PATH):
        print(MPTCP_OUTPUT_PATH)
        fd =  bpf_create_map(BPF_MAP_TYPE.BPF_MAP_TYPE_PERF_EVENT_ARRAY, ct.sizeof(ct.c_int), ct.sizeof(ct.c_int), CONFIG.mp_capable_perf_output.max_entries)
        bpf_obj_pin(fd, MPTCP_OUTPUT_PATH)
    return bpf_obj_get(MPTCP_OUTPUT_PATH)

def pin_mptcp_output_obj(obj):
    if not os.path.exists(MPTCP_OUTPUT_PATH):
        bpf_map__pin(obj, MPTCP_OUTPUT_PATH)
    return bpf_obj_get(MPTCP_OUTPUT_PATH)

def pin_mptcp_connects():
    if not os.path.exists(MPTCP_CONNECTS_PATH):
        fd = bpf_create_map(BPF_MAP_TYPE.BPF_MAP_TYPE_HASH, ct.sizeof(token_type), ct.sizeof(mptcp_connect), CONFIG.mptcp_connects.max_entries)
        bpf_obj_pin(fd, MPTCP_CONNECTS_PATH)
    return bpf_obj_get(MPTCP_CONNECTS_PATH)

def pin_mptcp_connects_obj(obj):
    if not os.path.exists(MPTCP_CONNECTS_PATH):
        bpf_map__pin(obj, MPTCP_CONNECTS_PATH)
    return bpf_obj_get(MPTCP_CONNECTS_PATH)

def pin_subflows():
    if not os.path.exists(SUBFLOWS_PATH):
        fd =bpf_create_map(BPF_MAP_TYPE.BPF_MAP_TYPE_HASH, ct.sizeof(tcp_4_tuple), ct.sizeof(subflow), CONFIG.subflows.max_entries)
        bpf_obj_pin(fd, SUBFLOWS_PATH)
    return bpf_obj_get(SUBFLOWS_PATH)

def pin_subflows_obj(obj):
    if not os.path.exists(SUBFLOWS_PATH):
        bpf_map__pin(obj, SUBFLOWS_PATH)
    return bpf_obj_get(SUBFLOWS_PATH)

def pin_tc_egress_tailcall_obj(obj):
    if not os.path.exists(TC_EGRESS_TAILCALL_PATH):
        bpf_map__pin(obj, TC_EGRESS_TAILCALL_PATH)
    return bpf_obj_get(TC_EGRESS_TAILCALL_PATH)

def pin_tc_egress_mpcapable_obj(obj):
    if not os.path.exists(TC_EGRESSS_MPCAPABLE_PATH):
        bpf_program__pin(obj, TC_EGRESSS_MPCAPABLE_PATH)
    return bpf_obj_get(TC_EGRESSS_MPCAPABLE_PATH)

def pin_tc_egress_join_obj(obj):
    if not os.path.exists(TC_EGRESSS_JOIN_PATH):
        bpf_program__pin(obj, TC_EGRESSS_JOIN_PATH)
    return bpf_obj_get(TC_EGRESSS_JOIN_PATH)

# input: 按照大端序排序的，原始的网络字节 8bytes  
# output: 按照大端序排序的，网络字节 4bytes   
def calc_sha1_token(key_byte_big):
    m = hashlib.sha1()
    m.update(key_byte_big)
    return m.digest()[:4]   # 4 bytes 

int2ip = lambda x: '.'.join([str(x//(256**i)%256) for i in range(3,-1,-1)])

#int val to bytes
def val_2_bytes(val, size, signed = False):
    return val.to_bytes(size, byteorder = "little", signed = signed)  # to be test 

#bytes to ctypes c_uint val
def bytes_2_val(bytes, signed = False):
    return int.from_bytes(bytes, byteorder = "little", signed = signed)

def unpin(path):
    if not path.startswith(CONFIG.bpf_virtual_fs_path):
        return 
    if not os.path.exists(CONFIG.bpf_virtual_fs_path):
        return 
    os.system("sudo rm -rf %s"%path)

def setzero(c_type_object):
    ct.memset(ct.byref(c_type_object), ct.c_int(0), ct.sizeof(c_type_object))


if __name__ == '__main__':
    import sys 
    key = int(sys.argv[1])
    t = calc_sha1_token(key.to_bytes(8, byteorder = "big", signed = False))
    print(int.from_bytes(t, byteorder = "big", signed = False))