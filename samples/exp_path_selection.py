#-*- coding:utf-8 -*-
import sys
sys.path.append("../src/py/emptcp")
from policy_chain import *

#local = ["223.3.71.76", "223.3.91.39", "223.3.78.49"]
#peer = ["223.3.71.41", "223.3.86.133", "223.3.86.134"]

local = ["172.16.12.128", "172.16.12.129", "172.16.12.130"]
peer = ["172.16.12.131", "172.16.12.132", "172.16.12.133"]

SELECTION_CHAIN = None 

#enabled 
rm_add_addr_exp = {
    "%s-%s"%(local[0], peer[0]) : {
        "recv_win" : 65535
    }
}

def set_rm_add_addr_exp_actions(flows, exp_config = rm_add_addr_exp):
    for l in local:
        for p in peer:
            flow = "%s-%s"%(l,p)
            if flow in exp_config:
                flows[flow].add("set_recv_win", recv_win = exp_config[flow]["recv_win"])
                flows[flow].add("rm_add_addr")
                flows[flow].submit()
            else:
                flows[flow].delete()

path_selection_exp = {
    "%s-%s"%(local[0], peer[0]) : {
        "recv_win" : 65535
    },
    "%s-%s"%(local[0], peer[1]) : {
        "recv_win" : 65535
    },
    
    "%s-%s"%(local[1], peer[2]) : {
        "recv_win" : 65535
    },
    "%s-%s"%(local[2], peer[2]): {
        "recv_win" : 65535
    }
}

def set_path_selection_exp_actions(exp_config = path_selection_exp):
    for l in local:
        for p in peer:
            flow = "%s-%s"%(l,p)
            if flow in exp_config:
                ac = XDPActionChain()
                ac.add("set_recv_win", recv_win = exp_config[flow]["recv_win"])
                pc = XDPPolicyChain(SELECTION_CHAIN, ac)
                pc.set(0, local_addr = l, remote_addr = p)
            else:
                ac = XDPActionChain()
                ac.add("set_flow_prio", backup = 1, addr_id = None)
                pc = XDPPolicyChain(SELECTION_CHAIN, ac)
                pc.set(0, local_addr = l, remote_addr = p)

def clear(): 
    sc = XDPPolicyChain(SELECTION_CHAIN)
    for l in local:
        for p in peer: 
            sc.delete(0, local_addr = l, remote_addr = p)

exp = {
    "selection" : set_path_selection_exp_actions,
    "clear" : clear
}
if __name__ == '__main__':
    XDPSelectorChain.config()
    XDPPolicyChain.config()

    SELECTION_CHAIN = XDPSelectorChain()
    if not SELECTION_CHAIN.init: 
        print("create new subflo")
        SELECTION_CHAIN.add("tcp2", selector_op_type_t.SELECTOR_OR)
        SELECTION_CHAIN.submit()
    import sys 
    exp_name = sys.argv[1]
    exp_fun = exp[exp_name]
    exp_fun()

