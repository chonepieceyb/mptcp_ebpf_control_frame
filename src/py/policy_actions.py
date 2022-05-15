#-*- coding:utf-8 -*-
from ctypes import byref
from bpf_map_def import *
from abc import abstractmethod
from data_struct_def import *
from utils import setzero, ArgWrapper
import argparse

class ActionBase:
    def __init__(self, direction, action_name):
        assert(direction in [Direction.INGRESS, Direction.EGRESS])
        self.direction = direction 
        self.name = action_name 
        if self.direction == Direction.INGRESS:
            self.name_idx_map = XDP_ACTION_NAME_IDX_MAP
        elif self.direction == Direction.EGRESS:
            self.name_idx_map = TC_E_ACTION_NAME_IDX_MAP
        else:
            raise RuntimeError("unkonw direction")
    @abstractmethod
    def dump(self):
        pass 
    @abstractmethod
    def __str__(self):
        pass 

    def _set_idx(self, action):
        if self.name not in self.name_idx_map:
            raise RuntimeError("action name :%s not exists"%self.name)
        action.chain.idx = self.name_idx_map[self.name]["tail_call_idx"]

def catch_mptcp_events_parser(arg_list):
    parser = argparse.ArgumentParser(description="catch_mptcp_events", prog = "catch mp_capable mp_join and fin events")
    args = parser.parse_args(arg_list)
    return vars(args)

class CatchMPTCPEvents(ActionBase):
    def __init__(self, direction):
        super().__init__(direction, "catch_mptcp_events_action")

    def dump(self):
        a = action_t()
        setzero(a)
        a.param_type = param_type_t.IMME
        self._set_idx(a)
        return a , None 

    def __str__(self):
        '''
        return print str 
        '''
        action_str = '''action_name: %s'''%self.name
        return action_str

class TcECatchMPTCPEvents(CatchMPTCPEvents):
    @ArgWrapper(catch_mptcp_events_parser)
    def __init__(self):
        super().__init__(Direction.EGRESS)

def rm_add_addr_parser(arg_list):
    parser = argparse.ArgumentParser(description="rm_add_addr", prog = "remove add addr option")
    args = parser.parse_args(arg_list)
    return vars(args)

class RemoveAddAddr(ActionBase):
    def __init__(self, direction):
        super().__init__(direction, "rm_add_addr_action")

    def dump(self):
        '''
        return action , param_bytes
        '''
        a = action_t()
        setzero(a)
        a.param_type = param_type_t.IMME
        self._set_idx(a)
        return a , None 

    def __str__(self):
        '''
        return print str 
        '''
        action_str = '''action_name: %s'''%self.name
        return action_str

class XDPRemoveAddAddr(RemoveAddAddr):
    @ArgWrapper(rm_add_addr_parser)
    def __init__(self):
        super().__init__(Direction.INGRESS)

class TcERemoveAddAddr(RemoveAddAddr):
    @ArgWrapper(rm_add_addr_parser)
    def __init__(self):
        super().__init__(Direction.EGRESS)

def set_recv_win_arg_parser(arg_list):
    parser = argparse.ArgumentParser(description="set recv win ingress action", prog = "set recv win")
    parser.add_argument("--recv_win", type = int,  required = True, help = "set packet recv window (0-65535) << win_shift")
    args = parser.parse_args(arg_list)
    return vars(args)

class SetRecvWin(ActionBase):
    def __init__(self,direction, *, recv_win):
        super().__init__(direction, "set_recv_win_action")
        self.recv_win = recv_win

    def dump(self):
        '''
        return action , param_bytes
        '''
        a = action_t()
        setzero(a)
        self._set_idx(a)
        a.param_type = param_type_t.IMME
        a.param.imme = ct.c_uint16(self.recv_win).value
        return a , None 

    def __str__(self):
        '''
        return print str 
        '''
        action_str = '''action_name: %s
recv_win:%d'''
        return action_str%(self.name, self.recv_win)

class XDPSetRecvWin(SetRecvWin):
    @ArgWrapper(set_recv_win_arg_parser)
    def __init__(self, **kw):
        super().__init__(Direction.INGRESS, **kw)

class TcESetRecvWin(SetRecvWin):
    @ArgWrapper(set_recv_win_arg_parser)
    def __init__(self, **kw):
        super().__init__(Direction.EGRESS, **kw)  

def set_flow_prio_arg_parser(arg_list):
    parser = argparse.ArgumentParser(description="set flow priority ingrtess", prog = "set flow priority")
    parser.add_argument("-B", "--backup", type = int, choices = [0,1], required = True, help = "set flow priority 1 (set flow as a backup flow)")
    parser.add_argument("-A", "--addr_id", type = int , help = "set address id will work on all flows with this addr id")
    args = parser.parse_args(arg_list)
    return vars(args)

class SetFlowPrio(ActionBase):
    def __init__(self, direction, *, backup, addr_id = None):
        super().__init__(direction, "set_flow_priority_action")
        self.backup = backup
        self.addr_id = addr_id

    def dump(self):
        '''
        return action
        '''
        a = action_t()
        setzero(a)
        self._set_idx(a)
        a.param_tyep = param_type_t.IMME
        
        imme = ct.c_int16(0)
        prio_opt_p = ct.cast(byref(imme), ct.POINTER(flow_prio_param_t))
        prio_opt_p.contents.B =self.backup

        if self.addr_id != None: 
            prio_opt_p.contents.A = 1
            prio_opt_p.contents.address_id = self.addr_id 
        else:
            prio_opt_p.contents.A = 0

        a.param.imme = imme.value
        return a , None 

    def __str__(self):
        '''
        return print str 
        '''
        if self.addr_id:
            action_str = '''backup: %d
addr_id: %d'''%(self.backup, self.addr_id)
        else: 
            action_str = '''backup: %d
addr_id: None'''%(self.backup)
        return "action_name: %s\n%s"%(self.name, action_str)

class XDPSetFlowPrio(SetFlowPrio):
    @ArgWrapper(set_flow_prio_arg_parser)
    def __init__(self, **kw):
        super().__init__(Direction.INGRESS, **kw)

class TcESetFlowPrio(SetFlowPrio):
    @ArgWrapper(set_flow_prio_arg_parser)
    def __init__(self, **kw):
        super().__init__(Direction.EGRESS, **kw)

if __name__ == '__main__':
    import sys 
    '''    
        a = SetRecvWinIngress(arg_list = sys.argv[1:])
        a_dump, _ = a.dump()
        print(a_dump.u2.imme)
        print(a.print())
    '''

    a = XDPSetFlowPrio(arg_list = sys.argv[1:]) 
    a_dump, _ = a.dump()

    imme = ct.c_int16(a_dump.param.imme)
    prio_opt_p = ct.cast(byref(imme), ct.POINTER(flow_prio_param_t))

    print("action: ", a_dump.chain.idx)
    print("imme: ",a_dump.param.imme)
    print("B: ", prio_opt_p.contents.B)
    print("A: ", prio_opt_p.contents.A)
    print("addr: ", prio_opt_p.contents.address_id)

    print(a)
