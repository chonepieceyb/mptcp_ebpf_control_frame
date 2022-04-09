#-*- coding:utf-8 -*-
from ctypes import byref
from xmlrpc.client import Boolean, boolean
from bpf_map_def import *
from abc import abstractmethod
from data_struct_def import *
from utils import setzero, ArgWrapper
import argparse

class ActionBase:
    def __init__(self, action_name, direction):
        assert(direction in [Direction.INGRESS, Direction.EGRESS])
        self.direction = direction 
        self.action_name = action_name 

    @abstractmethod
    def dump(self):
        pass 
    @abstractmethod
    def print(self):
        pass 

    def _get_tail_index(self):
        if self.direction == Direction.INGRESS:
            name_idx_map = XDP_TAILCALL_NAME_IDX_MAP
        else:
            raise RuntimeError("unkonw direction")

        if self.action_name not in name_idx_map:
            raise RuntimeError("action name :%s not exists"%self.action_name)
        return name_idx_map[self.action_name]["tail_call_idx"]

def set_recv_win_arg_parser(arg_list):
    parser = argparse.ArgumentParser(description="set recv win ingress action", prog = "set recv win")
    parser.add_argument("--recv_win", type = int,  required = True, help = "set packet recv window (0-65535) << win_shift")
    args = parser.parse_args(arg_list)
    return vars(args)

class SetRecvWinIngress(ActionBase):
    @ArgWrapper(set_recv_win_arg_parser)
    def __init__(self, *, recv_win):
        super().__init__("set_recv_win_ingress", Direction.INGRESS)
        self.recv_win = recv_win

    def dump(self):
        '''
        return action , param_bytes
        '''
        a = action()
        setzero(a)
        a.param_tyep = param_type_t.IMME
        a.u1.action = self._get_tail_index()
        a.u2.imme = ct.c_uint16(self.recv_win).value
        return a , None 

    def print(self):
        '''
        return print str 
        '''
        action_str = '''action_name: %s
recv_win:%d'''
        return action_str%(self.action_name, self.recv_win)

def set_flow_prio_arg_parser(arg_list):
    parser = argparse.ArgumentParser(description="set flow priority ingrtess", prog = "set flow priority")
    parser.add_argument("-B", "--backup", type = int, choices = [0,1], required = True, help = "set flow priority 1 (set flow as a backup flow)")
    parser.add_argument("-A", "--addr_id", type = int , help = "set address id will work on all flows with this addr id")
    args = parser.parse_args(arg_list)
    return vars(args)
    
class SetFlowPrioIngress(ActionBase):
    @ArgWrapper(set_flow_prio_arg_parser)
    def __init__(self, *, backup, addr_id = None):
        super().__init__("set_flow_priority_ingress", Direction.INGRESS)
        self.backup = backup
        self.addr_id = addr_id

    def dump(self):
        '''
        return action , param_bytes
        '''
        a = action()
        setzero(a)
        a.param_tyep = param_type_t.IMME
        a.u1.action = self._get_tail_index()
        
        imme = ct.c_int16(0)
        prio_opt_p = ct.cast(byref(imme), ct.POINTER(flow_prio_param_t))
        prio_opt_p.contents.B =self.backup

        if self.addr_id != None: 
            prio_opt_p.contents.A = 1
            prio_opt_p.contents.address_id = self.addr_id 
        else:
            prio_opt_p.contents.A = 0

        a.u2.imme = imme.value
        return a , None 

    def print(self):
        '''
        return print str 
        '''
        if self.addr_id:
            action_str = '''backup: %d
addr_id: %d'''%(self.backup, self.addr_id)
        else: 
            action_str = '''backup: %d
addr_id: None'''%(self.backup)
        return action_str

if __name__ == '__main__':
    import sys 
    '''    
        a = SetRecvWinIngress(arg_list = sys.argv[1:])
        a_dump, _ = a.dump()
        print(a_dump.u2.imme)
        print(a.print())
    '''
    a = SetFlowPrioIngress(arg_list = sys.argv[1:]) 
    a_dump, _ = a.dump()


    imme = ct.c_int16(a_dump.u2.imme)
    prio_opt_p = ct.cast(byref(imme), ct.POINTER(flow_prio_param_t))

    print("action: ", a_dump.u1.action)
    print("imme: ",a_dump.u2.imme)
    print("B: ", prio_opt_p.contents.B)
    print("A: ", prio_opt_p.contents.A)
    print("addr: ", prio_opt_p.contents.address_id)



    print(a.print())
