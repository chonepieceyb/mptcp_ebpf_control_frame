#-*- coding:utf-8 -*-]
import os 
import sys 
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PROJECT_PATH,"./src/py/emptcp"))
from policy_chain import *

import random 

local = ["223.3.71.76", "223.3.91.39", "223.3.78.49"]
peer = ["223.3.71.41", "223.3.86.133", "223.3.86.134"]


def test_tcp2_selector(sc):
    ac =  XDPActionChain()
    ac.add("set_recv_win", recv_win = 65535)
    sc.add("tcp2", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(0, local_addr = local[0], remote_addr = peer[0])

def test_tcp4_selector(sc):
    ac =  XDPActionChain()
    ac.add("set_recv_win", recv_win = 65535)
    sc.add("tcp4", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(0, local_addr = local[0], local_port = 60000, remote_addr = peer[0], remote_port = 5001)

def test_tcp_selector(sc):
    ac =  XDPActionChain()
    ac.add("set_recv_win", recv_win = 65535)
    sc.add("tcp", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(0)

def test_set_flow_prio(sc):
    ac =  XDPActionChain()
    ac.add("set_flow_prio", backup = 0)
    sc.add("tcp", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(0)

def test_rm_addaddr(sc):
    ac =  XDPActionChain()
    ac.add("rm_add_addr")
    sc.add("tcp", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(0)

def len2(sc):
    ac =  XDPActionChain()
    ac.add("set_recv_win", recv_win = 65535)
    sc.add("tcp", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(0)

def len4(sc):
    ac =  XDPActionChain()
    ac.add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535)
    sc.add("tcp", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(0)

def len8(sc):
    ac =  XDPActionChain()
    ac.add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535)
    sc.add("tcp4", selector_op_type_t.SELECTOR_OR).add("tcp4", selector_op_type_t.SELECTOR_OR).add("tcp2", selector_op_type_t.SELECTOR_OR).add("tcp", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(3)

def sel_tcp4(sc):
    #len2 
    ac =  XDPActionChain()
    ac.add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535)
    sc.add("tcp4", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    for i in range(6):
        pc.set(0, local_addr = '223.3.71.76', remote_addr = '223.3.71.41' , local_port = random.randint(1000,65535), remote_port = 5999)

def sel_tcp2(sc):
    #len2 
    ac =  XDPActionChain()
    ac.add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535)
    sc.add("tcp2", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(0, local_addr = '223.3.71.76', remote_addr = '223.3.71.41')

def sel_tcp(sc):
    #len2 
    ac =  XDPActionChain()
    ac.add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535).add("set_recv_win", recv_win = 65535)
    sc.add("tcp", selector_op_type_t.SELECTOR_AND)
    sc.submit()
    pc = XDPPolicyChain(sc, ac)
    pc.set(0)

exp = {
    "tcp2" : test_tcp2_selector,
    "tcp": test_tcp_selector,
    "tcp4": test_tcp4_selector,
    "prio": test_set_flow_prio,
    "rm_addr": test_rm_addaddr,
    "len2": len2,
    "len4": len4,
    "len8": len8,
    "sel_tcp": sel_tcp,
    "sel_tcp2" : sel_tcp2,
    "sel_tcp4" :sel_tcp4
}

if __name__ == '__main__':
    XDPSelectorChain.config()
    XDPPolicyChain.config()
    SELECTION_CHAIN = XDPSelectorChain()
    import sys 
    n = sys.argv[1]
    exp_func = exp[n]
    exp_func(SELECTION_CHAIN)