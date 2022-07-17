#-*- coding:utf-8 -*-
from policy_actions import * 
from policy_selectors import *
from config import CONFIG
from utils import *
from libbpf import *
from bpf_map_def import *
import uuid 


SEL_NAME_CMD_DICT = {
    "tcp4tuple_selector" : "tcp4",
    "tcp2tuple_selector" : "tcp2",
    "tcp_selector" : "tcp"
}

XDP_ACTION_DICT = {
    "set_recv_win" : XDPSetRecvWin,
    "set_flow_prio" : XDPSetFlowPrio,
    "rm_add_addr": XDPRemoveAddAddr
}

TC_EGRESS_ACTION_DICT = {
    "set_recv_win" : TcESetRecvWin,
    "catch_mptcp_events" : TcECatchMPTCPEvents,
    "set_flow_prio" : TcESetFlowPrio,
    "rm_add_addr": TcERemoveAddAddr
    # "msg_diff": TcEMsgDiff
}

XDP_SELECTOR_DICT = {
    "tcp4" : XDPTcp4TupleSelector,
    "tcp2" : XDPTcp2TupleSelector,
    "tcp"  : XDPTcpSelector
}

TC_EGRESS_SELECTOR_DICT = {
    "tcp2" : TcETcp2TupleSelector,
    "tcp" : TcETcpSelector
}

def add_selector(dict, name, op, **kw):
    sel_cls = dict[name]
    sel_cls.config()
    return sel_cls(op, **kw)

class SelectorChain:
    def __init__(self, direction, selector_chain_fd, *, should_init = False):
        self.init = False
        assert(selector_chain_fd > 0)
        self.selector_chain_fd = selector_chain_fd
        self.direction = direction 
        if self.direction == Direction.INGRESS:
            self.idx_name_map = XDP_SELECTOR_IDX_NAME_MAP
            self.selector_cls_dict = XDP_SELECTOR_DICT
        elif self.direction == Direction.EGRESS:
            self.idx_name_map = TC_E_SELECTOR_IDX_NAME_MAP
            self.selector_cls_dict = TC_EGRESS_SELECTOR_DICT
        else:
            raise RuntimeError("unkonw direction")
        self.selectors = []
        if should_init: 
            self._init_selectors()

    def __getitem__(self, key):
        assert(key >=0 and key < len(self.selectors))
        assert(self.init == True)
        return self.selectors[key]
    
    def add(self, cmd, op):
        assert(self.init == False)
        assert(len(self.selectors) < CONFIG.max_policy_len)
        sel_cls = self.selector_cls_dict[cmd]
        sel_cls.config()
        self.selectors.append(sel_cls(op))
        return self 

    def submit(self):
        assert(self.init == False)
        zero_key = ct.c_int(0)
        sel_chain = selector_chain_t()
        setzero(sel_chain)
        for idx, selector in enumerate(self.selectors): 
            sel_chain.selectors[idx] = selector.dump()
        bpf_map_update_elem(self.selector_chain_fd, ct.byref(zero_key), ct.byref(sel_chain))
        self.init = True 

    def _init_selectors(self): 
        zero_key = ct.c_int(0)
        selector_chain = selector_chain_t() 
        try:
            bpf_map_lookup_elem(self.selector_chain_fd, ct.byref(zero_key), ct.byref(selector_chain))
        except LinuxError: 
            return 

        for i in range(CONFIG.max_policy_len):
            try:
                selector = selector_chain.selectors[i] 
                self._parse_selector(selector)
            except Exception as e: 
                return 
        if len(self.selectors) != 0:
            self.init = True 

    def _parse_selector(self, selector):
        idx = selector.chain.idx 
        if idx == 0:
            return 
        op = selector.op
        name = self.idx_name_map[str(idx)]["tail_call_name"]
        cmd = SEL_NAME_CMD_DICT[name]
        sel_cls = self.selector_cls_dict[cmd]
        sel_cls.config()
        self.selectors.append(sel_cls(op))

class XDPSelectorChain(SelectorChain):
    xdp_selector_chain_path = XDP_SELECTOR_CHAIN_PATH
    is_config = False 

    @classmethod
    def config(cls):
        cls.selector_chain_fd = bpf_obj_get(cls.xdp_selector_chain_path)
        cls.is_config = True

    def __init__(self):
        assert(XDPSelectorChain.is_config)
        super().__init__(Direction.INGRESS, XDPSelectorChain.selector_chain_fd)    

class TCEgressSelectorChain(SelectorChain):
    tc_egress_selector_chain_path = TC_EGRESS_SELECTOR_CHAIN_PATH
    is_config = False 

    @classmethod
    def config(cls):
        cls.selector_chain_fd = bpf_obj_get(cls.tc_egress_selector_chain_path)
        cls.is_config = True

    def __init__(self):
        assert(TCEgressSelectorChain.is_config)
        super().__init__(Direction.EGRESS, TCEgressSelectorChain.selector_chain_fd)  

class ActionChain: 
    def __init__(self, direction):
        self.direction = direction 
        if self.direction == Direction.INGRESS:
            self.action_cls_map = XDP_ACTION_DICT
        elif self.direction == Direction.EGRESS:
            self.action_cls_map = TC_EGRESS_ACTION_DICT
        else:
            raise RuntimeError("unkonw direction")
        self.actions = []
        self.action_chain = None 

    def dump(self):
        if self.action_chain != None: 
            return self.action_chain 
        action_chain = action_chain_t()
        setzero(action_chain)
        for idx, action in enumerate(self.actions): 
            a_dump, _ = action.dump()
            action_chain.actions[idx] = a_dump
        self.action_chain = action_chain 
        return action_chain 

    def add(self, cmd, **kw):
        assert(len(self.actions) < CONFIG.max_policy_len) 
        self.actions.append(self.action_cls_map[cmd](**kw))
        self.action_chain = None 
        return self 

    def update(self, idx, cmd, **kw):
        assert(idx >=0 and idx < len(self.actions)) 
        self.actions[idx] = self.action_cls_map[cmd](**kw)
        self.action_chain = None 

    def pop(self):
        self.action_chain = None 
        return self.actions.pop()

    def clear(self):
        self.actions = []
        self.action_chain = None 

class XDPActionChain(ActionChain):
    def __init__(self):
        super().__init__(Direction.INGRESS)

class TCEgressActionChain(ActionChain):
    def __init__(self):
        super().__init__(Direction.EGRESS)

class ActionChains:
    def __init__(self, map_fd):
        assert(map_fd > 0)
        self.map_fd = map_fd 
    
    def create(self, action_chain):
        id = action_chain_id_t((uuid.uuid4().int) & ((1 << 64) - 1))
        chain = action_chain.dump()
        chain.ref_cnt = 1
        bpf_map_update_elem(self.map_fd, ct.byref(id), ct.byref(chain), BPF_MAP_UPDATE_ELEM_FLAG.BPF_NOEXIST)
        return id.value

    def update(self, action_chain_id):
        chain = action_chain_t()
        setzero(chain)
        id = action_chain_id_t(action_chain_id)
        bpf_map_lookup_elem(self.map_fd, ct.byref(id), ct.byref(chain))
        ref_cnt = chain.ref_cnt 
        chain.ref_cnt = ref_cnt + 1
        bpf_map_update_elem(self.map_fd, ct.byref(id), ct.byref(chain))
        return ref_cnt + 1

    def delete(self, action_chain_id):
        try: 
            chain = action_chain_t() 
            setzero(chain)
            id = action_chain_id_t(action_chain_id)
            bpf_map_lookup_elem(self.map_fd, ct.byref(id), ct.byref(chain))
            if chain.ref_cnt == 1 :
                bpf_map_delete_elem(self.map_fd, ct.byref(id))
            else: 
                chain.ref_cnt -= 1
                bpf_map_update_elem(self.map_fd, ct.byref(id), ct.byref(chain))
        except Exception as e: 
            pass 

class XDPActionChains(ActionChains):
    xdp_action_chains_path = XDP_ACTION_CHAINS_PATH
    is_config = False 
    @classmethod 
    def config(cls):
        cls.xdp_action_chains_fd = bpf_obj_get(cls.xdp_action_chains_path)
        cls.is_config = True 

    def __init__(self):
        assert(XDPActionChains.is_config)
        super().__init__(XDPActionChains.xdp_action_chains_fd)

class TCEgressActionChains(ActionChains):
    tc_egress_action_chains_path = TC_EGRESS_ACTION_CHAINS_PATH
    is_config = False 
    @classmethod 
    def config(cls):
        cls.tc_egress_action_chains_fd = bpf_obj_get(cls.tc_egress_action_chains_path)
        cls.is_config = True 

    def __init__(self):
        assert(TCEgressActionChains.is_config)
        super().__init__(TCEgressActionChains.tc_egress_action_chains_fd)

class PolicyChain:
    def __init__(self, action_chains, selector_chain, action_chain):
        self.selector_chain = selector_chain
        self.action_chain = action_chain
        self.action_chains = action_chains 

    def set(self, idx, *, action_chain_id = None, **kw):
        assert(self.action_chain != None and "set action chain is None")
        ref_cnt = None 
        try:
            #set action_chain first 
            if action_chain_id == None: 
                action_chain_id = self.action_chains.create(self.action_chain)
                ref_cnt = 1
            else:
                ref_cnt = self.action_chains.update(action_chain_id)
            
            #set selector 
            old_action_chain_id = self.selector_chain[idx].update(action_chain_id = action_chain_id, **kw)
            #delte old action chain id 
            self.action_chains.delete(old_action_chain_id)
        except Exception as e: 
            if ref_cnt != None : 
                self.action_chains.delete(action_chain_id)
            raise e 
        return action_chain_id 

    def delete(self, idx, **kw):
        try:
            old_action_chain_id = self.selector_chain[idx].delete(**kw)
            if old_action_chain_id != None : 
                self.action_chains.delete(old_action_chain_id)
        except Exception as e: 
            pass 

#ps: 感觉可以用装饰器简化代码，以后再研究吧
class XDPPolicyChain(PolicyChain):
    is_config = False 
    @classmethod
    def config(cls):
        XDPActionChains.config()
        cls.is_config = True 
       
    def __init__(self, selector_chain, action_chain = None):
        assert(XDPPolicyChain.is_config)
        super().__init__(XDPActionChains(), selector_chain, action_chain)

class TCEgressPolicyChain(PolicyChain):
    is_config = False 
    @classmethod
    def config(cls):
        TCEgressActionChains.config()
        cls.is_config = True 
       
    def __init__(self, selector_chain, action_chain = None):
        assert(TCEgressPolicyChain.is_config)
        super().__init__(TCEgressActionChains(), selector_chain, action_chain)

if __name__ == '__main__':
    '''
        #test xdp policy chain 
        XDPSelectorChain.config()
        XDPPolicyChain.config()
        sc = XDPSelectorChain()
        if not sc.init: 
            sc.add("tcp4", selector_op_type_t.SELECTOR_OR).add("tcp2", selector_op_type_t.SELECTOR_OR)
            sc.submit()

        ac = XDPActionChain()
        ac.add("set_recv_win", recv_win = 1500)

        pc = XDPPolicyChain(sc, ac)
        action_id = pc.set(1,local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
        pc.set(0, action_chain_id = action_id, local_addr = "172.16.12.128", remote_addr = "172.16.12.131", local_port = 1000, remote_port = 1000)
        
        while True: 
            try:
                pass
            except KeyboardInterrupt:
                pc.delete(1, local_addr = "172.16.12.128", remote_addr = "172.16.12.131")
                pc.delete(0, local_addr = "172.16.12.128", remote_addr = "172.16.12.131", local_port = 5000, remote_port = 5000)
                break 
    '''
    import time 
    XDPSelectorChain.config()
    XDPPolicyChain.config()
    sc = XDPSelectorChain()
    sc.add("tcp2", selector_op_type_t.SELECTOR_OR)
    sc.submit()

    ac = XDPActionChain()
    #ac.add("set_recv_win", recv_win = 1)
    ac.add("set_flow_prio", backup = 1)
    pc = XDPPolicyChain(sc, ac)
    #pc.set(0, remote_addr = "172.16.12.131", local_addr = "172.16.12.128")
    pc.set(0, remote_addr = "172.16.12.132", local_addr = "172.16.12.128")
    #pc.set(0, remote_addr = "172.16.12.133", local_addr = "172.16.12.128")
    pc.set(0, remote_addr = "172.16.12.131", local_addr = "172.16.12.129")
    #pc.set(0, remote_addr = "172.16.12.132", local_addr = "172.16.12.129")
    pc.set(0, remote_addr = "172.16.12.133", local_addr = "172.16.12.129")
    pc.set(0, remote_addr = "172.16.12.131", local_addr = "172.16.12.130")
    pc.set(0, remote_addr = "172.16.12.132", local_addr = "172.16.12.130")
    #pc.set(0, remote_addr = "172.16.12.133", local_addr = "172.16.12.130")