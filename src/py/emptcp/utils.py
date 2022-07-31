#-*- coding:utf-8 -*-
import hashlib
import os 
from config import CONFIG
import ctypes as ct 
from libbpf import *
from data_struct_def import *
from common import *

class ArgWrapper:
    def __init__(self, arg_parse_func, *, use_res_args = False):
        self.arg_parse_func = arg_parse_func
        self.use_res_args = use_res_args

    def __call__(self, func):
        def new_func(*args, **kw):
            kw_args = {}
            if "arg_list" in kw:
                if self.use_res_args: 
                    kw_args, res_args = self.arg_parse_func(kw.pop("arg_list"))
                    if res_args == None: 
                        res_args = []
                    kw_args["res_args"] = res_args
                else:
                    kw_args = self.arg_parse_func(kw.pop("arg_list"))
            else:
                kw_args = kw 
            return func(*args, **kw_args)
        return new_func

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

# input: 按照大端序排序的，原始的网络字节 8bytes  
# output: 按照大端序排序的，网络字节 4bytes   
def calc_sha1_token(key_byte_big):
    m = hashlib.sha1()
    m.update(key_byte_big)
    return m.digest()[:4]   # 4 bytes 

int2ip = lambda x: '.'.join([str(x//(256**i)%256) for i in range(3,-1,-1)])
ip2int = lambda ip: sum([256 ** j * int(i) for j, i in enumerate(ip.split('.')[::-1])])
mac2str = lambda x: ':'.join(["%02x"%b for b in x])

#int val to bytes
def val_2_bytes(val, size, signed = False):
    return val.to_bytes(size, byteorder = "little", signed = signed)  # to be test 

#bytes to ctypes c_uint val
def bytes_2_val(bytes, signed = False):
    return int.from_bytes(bytes, byteorder = "little", signed = signed)

def unpin(p, prefix = BPF_VFS_PREFIX):
    if (prefix != None) and (not p.startswith(prefix)):
        return 
    if not os.path.exists(p):
        return 
    os.system("sudo rm -rf %s"%p)

def setzero(c_type_object):
    ct.memset(ct.byref(c_type_object), ct.c_int(0), ct.sizeof(c_type_object))

def setvalue(c_type_object, v):
    ct.memset(ct.byref(c_type_object), ct.c_int(v), ct.sizeof(c_type_object))

def print_hex(bytes):
    l = ["%02x"%b for b in bytes]
    print(" ".join(l))

if __name__ == '__main__':
    print("local_ip %s"%int2ip(int.from_bytes(val_2_bytes(2148274348, 4), byteorder = "big", signed = False)))
    print("local_port %s"%int.from_bytes(val_2_bytes(29142, 2), byteorder = "big", signed = False))
    print("remote_ip %s"%int2ip(int.from_bytes(val_2_bytes( 2198605996, 4), byteorder = "big", signed = False)))
    print("remote_port %s"%int.from_bytes(val_2_bytes(24810, 2), byteorder = "big", signed = False))

    print(int2ip(569197332))