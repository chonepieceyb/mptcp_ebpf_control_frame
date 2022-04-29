#-*- coding:utf-8 -*-

from action_tool  import FlowIngressAction

#local = ["223.3.71.76", "223.3.91.39", "223.3.78.49"]
#peer = ["223.3.71.41", "223.3.86.133", "223.3.86.134"]

local = ["172.16.12.128", "172.16.12.129", "172.16.12.130"]
peer = ["172.16.12.131", "172.16.12.132", "172.16.12.133"]

def init_flows():
    flows  = {}
    for l in local: 
        for p in peer: 
            flows["%s-%s"%(l,p)] =  FlowIngressAction(local_addr = l, peer_addr = p)
    return flows 

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

def set_path_selection_exp_actions(flows, exp_config = path_selection_exp):
    for l in local:
        for p in peer:
            flow = "%s-%s"%(l,p)
            if flow in exp_config:
                flows[flow].add("set_recv_win", recv_win = exp_config[flow]["recv_win"])
            else:
                flows[flow].add("set_flow_prio", backup = 1, addr_id = None)

    for _, flow_action in flows.items():
        flow_action.submit()

exp = {
    "exp1" : set_rm_add_addr_exp_actions,
    "exp2" : set_path_selection_exp_actions
}
if __name__ == '__main__':
    FlowIngressAction.config()
    flows = init_flows()
    import sys 
    exp_name = sys.argv[1]
    exp_fun = exp[exp_name]
    exp_fun(flows)