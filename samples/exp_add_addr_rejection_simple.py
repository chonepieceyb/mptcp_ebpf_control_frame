#-*- coding:utf-8 -*-
import os 
import sys 
import socket as sk
import ctypes as ct

PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PROJECT_PATH,"./src/py/emptcp"))

from utils import *
from libbpf import *
from policy_chain import *
from policy_actions import * 
from eMPTCP_events import *
from data_struct_def import * 
from scapy import * 
import time 

local = ["172.16.12.128", "172.16.12.129"]
remote = ["172.16.12.131", "172.16.12.132"]

INTERVAL = 100
MAIN_LOCAL = local[0]
MAIN_REMOTE = remote[0]

ADDR_LIST = []
UN_SOCK = None 
XDP_SELECTOR_CHAIN = None 
DELETED = False 
starttime_ms = None 
is_recover = False 

def set_unsock():
    global UN_SOCK
    un_sock_path = "/tmp/emptcpd.socket"
    UN_SOCK = sk.socket(sk.AF_UNIX, sk.SOCK_SEQPACKET)
    UN_SOCK.connect(un_sock_path)

def setup_tc(): 
    TCEgressSelectorChain.config()
    TCEgressPolicyChain.config()
    selector_chain = TCEgressSelectorChain()
    if not selector_chain.init: 
        print("create new subflo")
        selector_chain.add("tcp", selector_op_type_t.SELECTOR_AND)
        selector_chain.submit()
    
    ac = TCEgressActionChain()
    ac.add("catch_mptcp_events")
    policy = TCEgressPolicyChain(selector_chain, ac)
    policy.set(0)

def setup_xdp():
    global XDP_SELECTOR_CHAIN
    XDPSelectorChain.config()
    XDPPolicyChain.config()
    XDP_SELECTOR_CHAIN = XDPSelectorChain()
    if not XDP_SELECTOR_CHAIN.init : 
        XDP_SELECTOR_CHAIN.add("tcp2", selector_op_type_t.SELECTOR_AND)
        XDP_SELECTOR_CHAIN.submit()
        set_rm_add_addr()

def set_rm_add_addr():
    global XDP_SELECTOR_CHAIN
    ac = XDPActionChain()
    ac.add("rm_add_addr")
    policy_chain = XDPPolicyChain(XDP_SELECTOR_CHAIN, ac)
    policy_chain.set(0, local_addr = MAIN_LOCAL, remote_addr = MAIN_REMOTE)

def set_recover_add_addr():
    global XDP_SELECTOR_CHAIN
    print("set recover action")
    ac = XDPActionChain()
    ac.add("recover_add_addr")
    policy_chain = XDPPolicyChain(XDP_SELECTOR_CHAIN, ac)
    policy_chain.set(0, local_addr = MAIN_LOCAL, remote_addr = MAIN_REMOTE) 

def delete_action():
    print("delete")
    policy_chain = XDPPolicyChain(XDP_SELECTOR_CHAIN)
    policy_chain.delete(0, local_addr = MAIN_LOCAL, remote_addr = MAIN_REMOTE) 

def process_mpc_event(mpc_e):
    global starttime_ms
    print("process process mpc event")
    if starttime_ms == None: 
        starttime_ms = round(time.time()*1000)

def process_rm_add_addr_event(rm_add_addr_e):
    global ADDR_LIST
    global DELETED 
    print("process rm_add_addr_event")
    if rm_add_addr_e.opt_len == 16: 
        ADDR_LIST.append(bytes(rm_add_addr_e.add_addr_opt[2:-2]))
        DELETED = False 
            #with port 
    elif rm_add_addr_e.opt_len == 18:
        ADDR_LIST.append(bytes(rm_add_addr_e.add_addr_opt[2:]))
        DELETED = False 
    elif rm_add_addr_e.opt_len == 8:
        ADDR_LIST.append(bytes(rm_add_addr_e.add_addr_opt[2:8]))
        DELETED = False 
    else: 
        raise RuntimeError("add addr len %d error :%d"%rm_add_addr_e.opt_len)
    
def process_recover_add_addr_event(recover_add_addr_e, **kw):
    # 1.get add addr opt
    # 2.build packet using add_addr opt and recover_add_addr_e 
    # 3.send built packet to emptcpd using UNIX sock
    global ADDR_LIST
    global DELETED
    if len(ADDR_LIST) != 0:
        pkt = RecoverAddAddr.build_packet(ADDR_LIST.pop(0), recover_add_addr_e)
        pkt_bytes = raw(pkt)
        UN_SOCK.send(pkt_bytes)
        #global pkt_list 
        #pkt_list.append(pkt)
        if len(ADDR_LIST) == 0:
            DELETED = True 
    if DELETED :
        delete_action() 

EVENT_MAP = {
    MP_CAPABLE_EVENT : mp_capable_event_t,
    MP_RM_ADD_ADDR : rm_add_addr_event_t,
    RECOVER_ADD_ADDR_EVENT : mptcp_copy_pkt_event_t,
}
EVENT_FUNC_MAP = {
    MP_CAPABLE_EVENT : process_mpc_event,
    MP_RM_ADD_ADDR : process_rm_add_addr_event,
    RECOVER_ADD_ADDR_EVENT : process_recover_add_addr_event,
}

def emptcp_events_callback(ctx, cpu,  data, size): 
    if size < ct.sizeof(eMPTCP_event_header_t):
        return 
    e = ct.cast(data, ct.POINTER(eMPTCP_event_header_t)).contents
    event = e.event 
    event_t = EVENT_MAP.get(event, None)
    if event_t == None :
        print("unkonwen event")
        return 
    EVENT_FUNC_MAP[event](ct.cast(data, ct.POINTER(event_t)).contents)

def schedule():
    global is_recover
    global starttime_ms
    if is_recover == True or starttime_ms == None:
        return 
    now_ms = round(time.time() * 1000)
    if now_ms - starttime_ms > INTERVAL: 
        print(now_ms - starttime_ms )
        set_recover_add_addr()
        is_recover = True 


if __name__ == '__main__':
    setup_tc()
    setup_xdp()
    set_unsock()
    tc_eMPTCP_events_fd = bpf_obj_get(TC_EGRESS_EMPTCP_EVENTS_PATH)
    xdp_eMPTCP_events_fd = bpf_obj_get(XDP_EMPTCP_EVENTS_PATH)
    with PerfBuffer(tc_eMPTCP_events_fd, emptcp_events_callback) as tpb, PerfBuffer(xdp_eMPTCP_events_fd, emptcp_events_callback) as xpb:
        print("begin")
        while True:
            try:
                tpb.poll(timeout_ms = 1)
                xpb.poll(timeout_ms = 1)
                schedule()
            except KeyboardInterrupt:
                break
            except Exception as e: 
                print(e)

