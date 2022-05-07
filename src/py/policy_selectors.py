#-*- coding:utf-8 -*-
from bpf_map_def import *
from abc import abstractmethod
from data_struct_def import *
from utils import *
from socket import inet_aton, htons 

class SelectorBase: 
    def __init__(self, direction, name, op):
        assert(direction in [Direction.INGRESS, Direction.EGRESS])
        assert(op in [selector_op_type_t.SELECTOR_AND, selector_op_type_t.SELECTOR_OR])
        self.direction = direction 
        self.op = op 
        self.name = name 
        if self.direction == Direction.INGRESS:
            self.name_idx_map = XDP_SELECTOR_NAME_IDX_MAP
        elif self.direction == Direction.EGRESS:
            self.name_idx_map = TC_E_SELECTOR_NAME_IDX_MAP
        else:
            raise RuntimeError("unkonw direction")

    def __str__(self):
        return "%s(%s)"%(self.name, selector_op_2_str[str(self.op)])

    def dump(self):
        s = selector_t()
        setzero(s)
        s.chain.idx = self._get_idx()
        s.op = self.op
        return s

    @abstractmethod
    def update(self, **kw):
        pass
    
    @abstractmethod
    def delete(self, **kw):
        #return action_id 
        pass
    
    @abstractmethod 
    def _config(self):
        pass 

    def _get_idx(self):
        if self.name not in self.name_idx_map:
            raise RuntimeError("selector name :%s not exists"%self.name)
        return self.name_idx_map[self.name]["tail_call_idx"]

class TcpSelector(SelectorBase):
    def __init__(self, direction, selector_op, map_fd):
        super().__init__(direction, "tcp_selector", selector_op)
        assert(map_fd > 0) 
        self.map_fd = map_fd 
    
    def update(self, *, action_chain_id):
        old_action_chain_id = None
        zero_key = ct.c_int(0)
        da = default_action_t()
        oda = default_action_t()
        da.id = action_chain_id
        da.enable = 1
        try:
            bpf_map_lookup_elem(self.map_fd, ct.byref(zero_key), ct.byref(oda))
            old_action_chain_id = oda.id 
        except LinuxError as e:
            pass
        finally:
            bpf_map_update_elem(self.map_fd, ct.byref(zero_key), ct.byref(da))
        return old_action_chain_id
     
    def delete(self):
        action_chain_id = None 
        
        zero_key = ct.c_int(0)
        da = default_action_t()
        setzero(da)
        try: 
            bpf_map_lookup_elem(self.map_fd, ct.byref(zero_key), ct.byref(da))
            action_chain_id = da.id
        except Exception as e: 
            pass 
        finally:
            if action_chain_id != None: 
                try:
                    bpf_map_delete_elem(self.map_fd, ct.byref(zero_key))
                except Exception: 
                    pass 
        return action_chain_id 

class TcETcpSelector(TcpSelector):
    tc_egress_tcp_default_action_path = TC_EGRESS_TCP_DEFAULT_ACTION_PATH
    is_config = False 

    @classmethod
    def config(cls):
        cls.map_fd  = bpf_obj_get(cls.tc_egress_tcp_default_action_path)
        cls.is_config = True 

    def __init__(self, selector_op):
        assert(TcETcpSelector.is_config)
        super().__init__(Direction.EGRESS, selector_op, TcETcpSelector.map_fd)

class Tcp2TupleSelector(SelectorBase):
    def __init__(self, direction ,selector_op, map_fd):
        super().__init__(direction, "tcp2tuple_selector", selector_op)
        assert(map_fd > 0) 
        self.map_fd = map_fd 
    
    def update(self, *, local_addr, remote_addr, action_chain_id):
        old_action_chain_id = None
        tcp2 = tcp2tuple()
        setzero(tcp2)
        tcp2.local_addr = bytes_2_val(inet_aton(local_addr))
        tcp2.remote_addr = bytes_2_val(inet_aton(remote_addr))
        _action_chain_id = action_chain_id_t(action_chain_id)
        _old_action_chain_id = action_chain_id_t()
        try:
            bpf_map_lookup_elem(self.map_fd, ct.byref(tcp2), ct.byref(_old_action_chain_id))
            old_action_chain_id = _old_action_chain_id.value
        except LinuxError:
            pass
        finally:
            bpf_map_update_elem(self.map_fd, ct.byref(tcp2), ct.byref(_action_chain_id))
        return old_action_chain_id

    def delete(self, *, local_addr, remote_addr):
        action_chain_id = None 
        tcp2 = tcp2tuple()
        _action_chain_id = action_chain_id_t()
        setzero(tcp2)
        tcp2.local_addr = bytes_2_val(inet_aton(local_addr))
        tcp2.remote_addr = bytes_2_val(inet_aton(remote_addr))
        try: 
            bpf_map_lookup_elem(self.map_fd, ct.byref(tcp2), ct.byref(_action_chain_id))
            action_chain_id = _action_chain_id.value
        except Exception as e:
            pass
        finally:
            if action_chain_id != None: 
                try:
                    bpf_map_delete_elem(self.map_fd, ct.byref(tcp2))
                except Exception: 
                    pass 
        return action_chain_id

class XDPTcp2TupleSelector(Tcp2TupleSelector):
    xdp_tcp2tuple_map_path = XDP_TCP2TUPLE_MAP_PATH
    is_config = False 

    @classmethod
    def config(cls):
        cls.map_fd  = bpf_obj_get(cls.xdp_tcp2tuple_map_path)
        cls.is_config = True 

    def __init__(self, selector_op):
        assert(XDPTcp2TupleSelector.is_config)
        super().__init__(Direction.INGRESS, selector_op, XDPTcp2TupleSelector.map_fd)

#Tc egress
class TcETcp2TupleSelector(Tcp2TupleSelector):
    tc_egress_tcp2tuple_map_path = TC_EGRESS_TCP2TUPLE_MAP_PATH
    is_config = False 

    @classmethod
    def config(cls):
        cls.map_fd  = bpf_obj_get(cls.tc_egress_tcp2tuple_map_path)
        cls.is_config = True 

    def __init__(self, selector_op):
        assert(TcETcp2TupleSelector.is_config)
        super().__init__(Direction.EGRESS, selector_op, TcETcp2TupleSelector.map_fd)

class Tcp4TupleSelector(SelectorBase):
    def __init__(self, direction, selector_op, map_fd):
        super().__init__(direction, "tcp4tuple_selector", selector_op)
        assert(map_fd > 0)
        self.map_fd = map_fd 
                                                                                                                                           
    def update(self, *, local_addr, remote_addr, local_port, remote_port, action_chain_id):
        old_action_chain_id = None 
        tcp4 = tcp4tuple()
        setzero(tcp4)
        tcp4.local_addr = bytes_2_val(inet_aton(local_addr))
        tcp4.remote_addr = bytes_2_val(inet_aton(remote_addr))
        tcp4.local_port= htons(local_port)
        tcp4.remote_port = htons(remote_port)
        _action_chain_id = action_chain_id_t(action_chain_id)
        _old_action_chain_id = action_chain_id_t()
        try:
            bpf_map_lookup_elem(self.map_fd, ct.byref(tcp4), ct.byref(_old_action_chain_id))
            old_action_chain_id = _old_action_chain_id.value
        except LinuxError:
            pass
        finally:
            bpf_map_update_elem(self.map_fd, ct.byref(tcp4), ct.byref(_action_chain_id))
        return old_action_chain_id 

    def delete(self, *, local_addr, remote_addr, local_port, remote_port):
        action_chain_id = None 
        
        tcp4 = tcp4tuple()
        _action_chain_id = action_chain_id_t(0)
        setzero(tcp4)
        tcp4.local_addr = bytes_2_val(inet_aton(local_addr))
        tcp4.remote_addr = bytes_2_val(inet_aton(remote_addr))
        tcp4.local_port= htons(local_port)
        tcp4.remote_port = htons(remote_port)
        try:
            bpf_map_lookup_elem(self.map_fd, ct.byref(tcp4), ct.byref(_action_chain_id))      
            action_chain_id = _action_chain_id.value
        except Exception as e:
            pass
        finally:
            if action_chain_id != None:
                try:
                    bpf_map_delete_elem(self.map_fd, ct.byref(tcp4))
                except Exception:
                    pass 
        return action_chain_id 

class XDPTcp4TupleSelector(Tcp4TupleSelector):
    xdp_tcp4tuple_map_path = XDP_TCP4TUPLE_MAP_PATH
    is_config = False 
    @classmethod
    def config(cls):
        cls.map_fd  = bpf_obj_get(cls.xdp_tcp4tuple_map_path)
        cls.is_config = True 

    def __init__(self, selector_op):
        assert(XDPTcp4TupleSelector.is_config)
        super().__init__(Direction.INGRESS, selector_op, XDPTcp4TupleSelector.map_fd)                                                                                                                          

if __name__ == '__main__': 
    XDPTcp2TupleSelector.config()
    XDPTcp4TupleSelector.config()

    tcp2 = XDPTcp2TupleSelector(selector_op_type_t.SELECTOR_OR)
    tcp4= XDPTcp4TupleSelector(selector_op_type_t.SELECTOR_AND)
    
    tcp2.dump()
    tcp4.dump()
    
    print(tcp2)
    print(tcp4)

    print(tcp2.update(local_addr = "127.0.0.1", remote_addr = "128.0.0.1", action_chain_id = 1))
    print(tcp4.update(local_addr = "127.0.0.1", remote_addr = "128.0.0.1", local_port = 6000, remote_port = 5000, action_chain_id = 3))