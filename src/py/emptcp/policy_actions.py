#-*- coding:utf-8 -*-
from ctypes import byref
from bpf_map_def import *
from abc import abstractmethod
from data_struct_def import *
from utils import *
from scapy.all import Ether, IP, raw, TCP, hexdump
import socket 
import argparse
from eMPTCP_events import *

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

def recover_add_addr_parser(arg_list):
    parser = argparse.ArgumentParser(description="recover_add_addr", prog = "recover add addr option")
    args = parser.parse_args(arg_list)
    return vars(args)

class RecoverAddAddr(ActionBase):
    @staticmethod 
    def build_packet(add_addr_opt_bytes, copy_pkt_event):
        # 先不放 timestamp 选项试一下
        #(30,b'\x10\x07\x53\x20\xda\xef\x45\x73\x96\xf4')
        options = []
        opt_len = 0
        add_addr_opt = (30, add_addr_opt_bytes)
        opt_len = opt_len + 2 + len(add_addr_opt_bytes)   
        '''
            dss_bytes = bytearray(copy_pkt_event.dss_opt)[2:]  # without first 2 bytes of kind and len 
            if copy_pkt_event.dss_opt.a :
                #8bytes
                dss_bytes.extend(bytes(bytearray(copy_pkt_event.dss_ack)[0:8])) #little end?
            else :
                dss_bytes.extend(bytes(bytearray(copy_pkt_event.dss_ack)[0:4])) #little end?
            dss_opt = (30, bytes(dss_bytes))
        
            opt_len = opt_len + len(dss_bytes) + 2
        '''
        #nop 
        if opt_len % 4 != 0 :
            res_opt_len = (4 - opt_len % 4) 
            for i in range(0, res_opt_len) : 
                options.append((1,b''))                                                           
        options.append(add_addr_opt)
        #options.append(dss_opt)
        
        seq = socket.ntohl(copy_pkt_event.seq)
        ack = socket.ntohl(copy_pkt_event.ack_seq)
        pkt = Ether(dst=mac2str(copy_pkt_event.eth.h_dest), src=mac2str(copy_pkt_event.eth.h_source))/\
            IP(src=int2ip(socket.ntohl(copy_pkt_event.flow.remote_addr)), dst=int2ip(socket.ntohl(copy_pkt_event.flow.local_addr)))/\
            TCP(window = socket.ntohs(copy_pkt_event.window),sport=socket.ntohs(copy_pkt_event.flow.remote_port), dport = socket.ntohs(copy_pkt_event.flow.local_port), flags ='A',seq = seq, ack = ack, options=options)
        return pkt

    def __init__(self, direction): 
        super().__init__(direction, "copy_pkt_action")

    def dump(self):
        '''
        return action , param_bytes
        '''
        a = action_t()
        setzero(a)
        a.param_type = param_type_t.IMME
        self._set_idx(a)
        a.param.imme = RECOVER_ADD_ADDR_EVENT
        return a , None 

    def __str__(self):
        '''
        return print str 
        '''
        action_str = '''action_name: %s'''%self.name
        return action_str

class XDPRecoverAddAddr(RecoverAddAddr):
    @ArgWrapper(recover_add_addr_parser)
    def __init__(self):
        super().__init__(Direction.INGRESS)

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
    @staticmethod 
    def build_packet(copy_pkt_event):
        # 先不放 timestamp 选项试一下
        #(30,b'\x10\x07\x53\x20\xda\xef\x45\x73\x96\xf4')
        options = []
        
        mp = mp_prio()
        setzero(mp)
        mp.b = 0
        mp.sub = 5
        print_hex(bytearray(mp)[2:])
        mp_prio_opt = (30, bytes(bytearray(mp)[2:]))
        #nop 
        options.append((1,b''))                                                           
        options.append(mp_prio_opt)
        seq = socket.ntohl(copy_pkt_event.seq)
        ack = socket.ntohl(copy_pkt_event.ack_seq)
        pkt = Ether(dst=mac2str(copy_pkt_event.eth.h_dest), src=mac2str(copy_pkt_event.eth.h_source))/\
            IP(src=int2ip(socket.ntohl(copy_pkt_event.flow.remote_addr)), dst=int2ip(socket.ntohl(copy_pkt_event.flow.local_addr)))/\
            TCP(window = socket.ntohs(copy_pkt_event.window),sport=socket.ntohs(copy_pkt_event.flow.remote_port), dport = socket.ntohs(copy_pkt_event.flow.local_port), flags ='A',seq = seq, ack = ack, options=options)
        return pkt

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

class Record(ActionBase):
    def __init__(self, direction, *, pkt = True, flow = True, rtt = True):
        super().__init__(direction, "set_flow_priority_action")
        self.pkt = pkt 
        self.flow = flow 
        self.rtt = rtt 

    def dump(self):
        '''
        return action
        '''
        a = action_t()
        setzero(a)
        self._set_idx(a)
        a.param_tyep = param_type_t.IMME
        
        imme = ct.c_int16(0)
        metric_p = ct.cast(byref(imme), ct.POINTER(metric_param_t))
        metric_p.contents.pkt = self.pkt 
        metric_p.contents.flow = self.flow
        metric_p.contents.rtt = self.rtt

        a.param.imme = imme.value
        return a , None 

    def __str__(self):
        '''
        return print str 
        '''
        action_str = '''pkt: %d
flow: %d
rtt: %d'''%(self.pkt, self.flow, self.rtt)
        return "action_name: %s\n%s"%(self.name, action_str)

class XDPRecord(Record):
    def __init__(self, **kw):
        super().__init__(Direction.INGRESS, **kw)


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
