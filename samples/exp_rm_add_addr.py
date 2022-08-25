#-*- coding:utf-8 -*-
#-*- coding:utf-8 -*-
import sys
import os 
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(PROJECT_PATH,"./src/py/emptcp"))
from policy_chain import *

#local = ["223.3.71.76", "223.3.91.39", "223.3.78.49"]
#peer = ["223.3.71.41", "223.3.86.133", "223.3.86.134"]

local = ["172.16.12.128", "172.16.12.129"]
peer = ["172.16.12.131", "172.16.12.132"]

SELECTION_CHAIN = None 

#enabled 
rm_add_addr_exp = {
    "%s-%s"%(local[0], peer[0]) : {
    }
}

def set_rm_add_addr_exp_actions(exp_config = rm_add_addr_exp):
    for l in local:
        for p in peer:
            flow = "%s-%s"%(l,p)
            if flow in exp_config:
                ac = XDPActionChain()
                recv_win = exp_config[flow].get("recv_win", None)
                if recv_win != None: 
                    ac.add("set_recv_win", recv_win = exp_config[flow]["recv_win"])
                ac.add("rm_add_addr")
                pc = XDPPolicyChain(SELECTION_CHAIN, ac)
                pc.set(1, local_addr = l, remote_addr = p)
            else:
                pc = XDPPolicyChain(SELECTION_CHAIN)
                pc.delete(1, local_addr = l, remote_addr = p)

def clear(): 
    pc = XDPPolicyChain(SELECTION_CHAIN)
    for l in local:
        for p in peer: 
            pc.delete(1, local_addr = l, remote_addr = p)

exp = {
    "rm_add_addr" : set_rm_add_addr_exp_actions,
    "clear" : clear
}

if __name__ == '__main__':
    XDPSelectorChain.config()
    XDPPolicyChain.config()

    SELECTION_CHAIN = XDPSelectorChain()
    if not SELECTION_CHAIN.init: 
        print("create new subflo")
        SELECTION_CHAIN.add("tcp4", selector_op_type_t.SELECTOR_OR).add("tcp2", selector_op_type_t.SELECTOR_AND)
        SELECTION_CHAIN.submit()
    
    import sys 
    if len(sys.argv) > 1: 
        exp["clear"]()
    else:
        exp["rm_add_addr"]()

