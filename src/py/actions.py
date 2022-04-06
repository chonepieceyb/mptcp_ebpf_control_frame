#-*- coding:utf-8 -*-
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

if __name__ == '__main__':
    import sys 
    a = SetRecvWinIngress(arg_list = sys.argv[1:])
    a_dump, _ = a.dump()
    print(a_dump.u2.imme)
    print(a.print())

        

