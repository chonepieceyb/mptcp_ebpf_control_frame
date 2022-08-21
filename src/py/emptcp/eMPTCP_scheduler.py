#-*- coding:utf-8 -*-
from policy_chain import *
from bpf_map_def import * 
from utils import * 
from abc import abstractmethod
import uuid 
import queue
from functools import partial
import time
import socket as sk 
from socket import *
from multiprocessing import  Process, Queue, Value, cpu_count
from pexecute.process import ProcessLoom
import queue
import heapq
from math import ceil
from policy_actions import RecoverAddAddr
from eMPTCP_events import *

def setup_tc(): 
    TCEgressSelectorChain.config()
    TCEgressPolicyChain.config()
    selector_chain = TCEgressSelectorChain()
    if not selector_chain.init: 
        print("create new subflo")
        selector_chain.add("tcp", selector_op_type_t.SELECTOR_AND)
        selector_chain.submit()
    
    ac = TCEgressActionChain()
    ac.add("catch_mptcp_events")

    policy = TCEgressPolicyChain(selector_chain, ac)
    policy.set(0)

def setup_unsock(): 
    un_sock_path = "/tmp/emptcpd.socket"
    client = sk.socket(sk.AF_UNIX, sk.SOCK_SEQPACKET)
    client.connect(un_sock_path)
    return client

UN_SOCK = None 

##################errors#####################
class eMPTCPTcpflowError(Exception):
    def __init__(self, error, tcpflow):
        super().__init__(self) #初始化父类
        self.errorinfo= error
        self.tcpflow = tcpflow

    def __str__(self):
        return self.errorinfo

class eMPTCPTcpflowAddError(eMPTCPTcpflowError):
    def __init__(self, tcpflow):
        super().__init__("tcp flow exists!", tcpflow)

##################errors#####################

class SubflowInfo: 
    xdp_selector_chain = None
    @classmethod
    def setup(cls): 
        XDPSelectorChain.config()
        XDPPolicyChain.config()
        cls.xdp_selector_chain = XDPSelectorChain()
        if not cls.xdp_selector_chain.init : 
            cls.xdp_selector_chain.add("tcp4", selector_op_type_t.SELECTOR_OR).add("tcp", selector_op_type_t.SELECTOR_AND)
            cls.xdp_selector_chain.submit()
        '''   
            ac = XDPActionChain()
            ac.add("rm_add_addr")
            policy_chain = XDPPolicyChain(cls.xdp_selector_chain, ac)
            policy_chain.set(1)
        ''' 

    @classmethod
    def take_action(cls, action, flow):
        assert(isinstance(action, eMPTCPConnection.Action) and "not action")
        ac = XDPActionChain()
        if action.recv_win_ingress != None: 
            ac.add("set_recv_win", recv_win = action.recv_win_ingress)
        if action.rm_add_addr != None and action.rm_add_addr == True: 
            ac.add("rm_add_addr")
        if action.recover_add_addr != None and action.recover_add_addr == True: 
            ac.add("recover_add_addr")
        if action.backup != None and action.backup == True:
            ac.add("set_flow_prio", backup = 1, addr_id = None)

        if ac.len() > 0:
            policy_chain = XDPPolicyChain(cls.xdp_selector_chain, ac)
            policy_chain.set(0, tcp4 = flow)
        else: 
            policy_chain = XDPPolicyChain(cls.xdp_selector_chain)
            policy_chain.delete(0, tcp4 = flow)

    @classmethod
    def delete_action(cls, flow):
        policy_chain = XDPPolicyChain(cls.xdp_selector_chain)
        policy_chain.delete(0, tcp4 = flow)

    def __init__(self,flow,*,start_us,**kw):
        assert(len(flow) == 4)
        self.action = eMPTCPConnection.Action()   #recall the current action 
        self.flow = flow 
        self.start_us = start_us 
        self.backup_pkt = None 

    def push_backup_pkt(self, e):
        if self.backup_pkt == None or self.backup_pkt.ack_seq < e.ack_seq:
            self.backup_pkt = e
    
    def pop_backup_pkt(self):
        pkt = self.backup_pkt
        self.backup_pkt = None 
        return pkt 

class eMPTCPConnection:
    class Action: 
        def __init__(self):
            #decisiton attributes 
            self.recv_win_ingress = None
            self.rm_add_addr = False       #rm_add_addr and recover_add_addr should not be true at the same time 
            self.recover_add_addr = False 
            self.backup = False 
            self.recover_flow = False   #trigger recover flow action 
            pass

    #tcp4tuple (local_port, remote_port, local_addr, remote_addr)

    def __init__(self, *, local_token, remote_token):
        self.id = uuid.uuid4()
        self.local_token = local_token 
        self.remote_token = remote_token 
        self.subflows = {}  #key tcp 4 元组， value : eMPTCPSubflow
        self.add_addr_opt_list = []
        self.main_flow = None

    def __lt__(self, other):
        #compare for heap in scheduler 
        return True

    def infos(self):
        return self.subflows.values()

    def flows(self):
        return self.subflows.keys()

    def items(self):
        return self.subflows.items()

    def  __getitem__(self, key):
        return self.subflows[key]

    def add(self, tcpflow, **kw):
        if tcpflow in self.subflows: 
            raise eMPTCPTcpflowAddError(tcpflow)
        s =  SubflowInfo(tcpflow, **kw)
        self.subflows[tcpflow] = s
        return s

    def pop(self, tcpflow):
        SubflowInfo.delete_action(tcpflow) 
        return self.subflows.pop(tcpflow, None)

    def empty(self):
        return len(self.subflows) == 0

    def length(self):
        return len(self.subflows) 

    def push_add_addr_opt(self, rm_add_addr_e):
        if rm_add_addr_e.opt_len == 16: 
            self.add_addr_opt_list.append(bytes(rm_add_addr_e.add_addr_opt[2:-2]))
            #with port 
        elif rm_add_addr_e.opt_len == 18:
            self.add_addr_opt_list.append(bytes(rm_add_addr_e.add_addr_opt[2:]))
        elif rm_add_addr_e.opt_len == 8:
            self.add_addr_opt_list.append(bytes(rm_add_addr_e.add_addr_opt[2:8]))
        else: 
            raise RuntimeError("add addr len %d error :%d"%rm_add_addr_e.opt_len)
        
    def pop_add_addr_opt(self):
        if len(self.add_addr_opt_list) == 0:
            return None 
        else:
            return self.add_addr_opt_list.pop(0)
## Policy
class SchedulerPolixy: 
    def __init__(self):
        pass 

    @abstractmethod
    def make(self, emptcp_connection):
        '''
            @param  
                emptcp_connection: eMPTCPConnection object 
                set decisiton attributes in emptcp_connection 
            return: 
                return next intervel and subflows needs to be update [subflows]
                interval, remote_token, [(flow, action), (flow, action)]
        '''
        pass 

class TestPolicy(SchedulerPolixy): 
    def __init__(self):
        super().__init__()
        pass 

    def make(self, emptcp_connection):
        assert(isinstance(emptcp_connection, eMPTCPConnection))
        actions = []
        for info in emptcp_connection.infos():
            if info.action.recv_win_ingress == None:
                action =  eMPTCPConnection.Action()
                action.recv_win_ingress = 65535
                actions.append((info.flow, action))
        return 50, emptcp_connection.remote_token, actions

def print_tcp4_flow(flow):
    print("local_ip %s"%int2ip(int.from_bytes(val_2_bytes(flow.local_addr, 4), byteorder = "big", signed = False)))
    print("local_port %s"%int.from_bytes(val_2_bytes(flow.local_port, 2), byteorder = "big", signed = False))
    print("remote_ip %s"%int2ip(int.from_bytes(val_2_bytes(flow.remote_addr, 4), byteorder = "big", signed = False)))
    print("remote_port %s"%int.from_bytes(val_2_bytes(flow.remote_port, 2), byteorder = "big", signed = False))

event_map = {
    MP_CAPABLE_EVENT : mp_capable_event_t,
    MP_JOIN_EVENT : mp_join_event_t,
    FIN_EVENT : fin_event_t,
    MP_RM_ADD_ADDR : rm_add_addr_event_t,
    RECOVER_ADD_ADDR_EVENT : mptcp_copy_pkt_event_t,
    MP_PRIO_BACKUP_EVENT : mptcp_copy_pkt_event_t,
}

def eMPTCP_event_process_func(q, running):
    def store_eMPTCP_events(queue, ctx, cpu,  data, size):
        if size < ct.sizeof(eMPTCP_event_header_t):
            return 
        e = ct.cast(data, ct.POINTER(eMPTCP_event_header_t)).contents
        event = e.event 
        event_t = event_map.get(event, None)
        if event_t == None :
            raise RuntimeError("unkonwn event :%d"%event)
        queue.put(ct.cast(data, ct.POINTER(event_t)).contents)

    tc_eMPTCP_events_fd = bpf_obj_get(TC_EGRESS_EMPTCP_EVENTS_PATH)
    xdp_eMPTCP_events_fd = bpf_obj_get(XDP_EMPTCP_EVENTS_PATH)
    with PerfBuffer(tc_eMPTCP_events_fd, partial(store_eMPTCP_events, q)) as tpb, PerfBuffer(xdp_eMPTCP_events_fd, partial(store_eMPTCP_events, q)) as xpb:
        while running.value:
            try:
                tpb.poll(timeout_ms = 10)
                xpb.poll(timeout_ms = 10)
            except KeyboardInterrupt:
                break

pkt_list = []

class eMPTCPScheduler:
    def __init__(self, policy, *, init_interval = 0 , parallel_ths = 100, parallel_level = cpu_count()):
        assert(isinstance(policy, SchedulerPolixy))
        self.policy = policy 
        self.eMPTCP_events_q = Queue()
        self.init_interval = init_interval
        self.remote_token_mpc_dict = {}
        self.local_token_mpc_dict = {}
        self.tcpflows = {}   #(MPTCP connection, MPTCP subflow)
        self.running = Value('b', False)  
        self.parallel_level = parallel_level
        self.parallel_ths = parallel_ths
        self.loom = ProcessLoom(max_runner_cap=parallel_level)
        self.scheduler_heapq = []     #(token, time)
        self.un_sock = None
        self.event_func_map = {
            MP_CAPABLE_EVENT : self._process_mpc_event,
            MP_JOIN_EVENT : self._process_mpj_event,
            FIN_EVENT : self._process_fin_event,
            MP_RM_ADD_ADDR : self._process_rm_add_addr_event,
            RECOVER_ADD_ADDR_EVENT : self._process_recover_add_addr_event,
            MP_PRIO_BACKUP_EVENT : self._porcess_mp_prio_backup_event
        }

    def start(self):
        self.running.value = True
        self.eMPTCP_event_process = Process(target = eMPTCP_event_process_func, args = [self.eMPTCP_events_q, self.running])
        self.eMPTCP_event_process.start()
        self._run()

    def _run(self):
        #consumer
        while True :
            now = time.time()*1000
            try:
                #schedule one connection 
                try:
                    e = self.eMPTCP_events_q.get(True, timeout = 0.01)
                    try:
                        event = e.header.event 
                        event_func = self.event_func_map.get(event, None)
                        if event_func == None: 
                            raise RuntimeError("unkonwn event :%d"%event)
                        event_func(e, now_ms = now)
                    except Exception as e: 
                        print(e)
                except queue.Empty:
                    pass 
                try:
                    connections = self._get_available_connections(now)
                    self._schedule(connections)
                except Exception as e:
                    print(e)
            except KeyboardInterrupt:
                self.running.value = False 
                while not self.eMPTCP_events_q.empty():
                    _ = self.eMPTCP_events_q.get(True, timeout = 0.01)
                self.eMPTCP_event_process.join()
                break
                
    def _get_available_connections(self, now):
        connections = []
        rt_set = set()
        while True and not len(self.scheduler_heapq) == 0: 
            currt = self.scheduler_heapq[0][0]
            if now >= currt:
                c = heapq.heappop(self.scheduler_heapq)[1]
                if c.remote_token not in rt_set:
                    connections.append(c)
                    rt_set.add(c.remote_token)
            else:
                break 
        return connections

    def _get_policies(self, connections):
        #use process loom 
        def batch_func(cons):
            l1 = []
            subl = []
            for c in cons:
                try:
                    intv, rt, actions = self.policy.make(c)
                    l1.append((intv, rt))
                    subl.extend(actions)
                except Exception as e:
                    print(e) 
            return l1, subl 
        
        if (len(connections) < self.parallel_ths):
            return batch_func(connections)
            
        batch_size = ceil(len(connections) / self.parallel_level)
        for b in range(self.parallel_level):
            begin = b*batch_size
            if (begin >= len(connections)) :
                break
            end = (b+1)*batch_size
            if end < len(connections) : 
                self.loom.add_function(batch_func, [connections[begin:end]])
            else:
                self.loom.add_function(batch_func, [connections[begin:]])
        outputs = self.loom.execute()
        next_l = []
        actions = []
        for output in outputs.values():
            if not output["got_error"]:
                next_l.extend(output["output"][0])
                actions.extend(output["output"][1])
        return next_l, actions
    
    def _take_policies(self, actions):
        def recover_flow(flow, a): 
            _, tcpf = self.tcpflows.get(flow, (None, None))
            if tcpf == None: 
                raise RuntimeError("recover subflow tcp flow not exists!")
            back_pkt = tcpf.pop_backup_pkt()
            if back_pkt != None:
                pkt = SetFlowPrio.build_packet(back_pkt)
                self.un_sock.send(raw(pkt))
                print("send copy pkt")
                a.backup = False 
                a.recover_flow = False 

        def batch_func(acs):
            for f, a in acs:
                try:
                    SubflowInfo.take_action(a, f)    #modify BPF MAP 
                except Exception as e:
                    print(e)
                if a.recover_flow: 
                    recover_flow(f, a)

        if (len(actions) < self.parallel_ths):
            batch_func(actions)
            return  

        batch_size = ceil(len(actions) / self.parallel_level)
        for b in range(self.parallel_level):
            begin = b*batch_size
            if (begin > len(actions)) :
                break
            end = (b+1)*batch_size
            if end < len(actions) : 
                self.loom.add_function(batch_func, [ actions[begin:end] ])
            else:
                self.loom.add_function(batch_func, [ actions[begin:] ])
        self.loom.execute()

    def _schedule(self, connections):
        if len(connections) == 0:
            return
        try:
            next_l, actions = self._get_policies(connections)
            self._take_policies(actions)
            now = round(time.time()*1000)
            #re add to schedule_heapq
            bias = 0
            for l in next_l : 
                if l[1] not in self.remote_token_mpc_dict:
                    continue 
                heapq.heappush(self.scheduler_heapq, (l[0]+now+bias, self.remote_token_mpc_dict[l[1]]))
                bias+=1

            for flow, action in actions: 
                if flow in  self.tcpflows:
                    self.tcpflows[flow][1].action = action 

        except Exception as e: 
            print(e)

    def _process_mpc_event(self, mpce, *, now_ms, **kw):
        tcpf = self._get_tcpflow(mpce.flow)
        if not self._check_black_list(tcpf):
            return 
        rk = mpce.remote_key
        rt_b =  calc_sha1_token(val_2_bytes(rk, 8))
        rt = bytes_2_val(rt_b)
        lk = mpce.local_key
        lt_b =  calc_sha1_token(val_2_bytes(lk, 8))
        lt = bytes_2_val(lt_b)
        #create new mptcp connection 
        if rt in self.remote_token_mpc_dict: 
            raise RuntimeError("mptcp rt cal exisits!, %d"%rt) 
        if lt in self.local_token_mpc_dict: 
            raise RuntimeError("mptcp lt cal exisits!, %d"%lt) 
        if tcpf in self.tcpflows:
            print_tcp4_flow(mpce.flow)
            raise RuntimeError("tcp flow exists!")
        c = eMPTCPConnection(local_token = lt, remote_token = rt)
        s = c.add(tcpf, start_us = round(now_ms * 1000))
        c.main_flow = s
        self.remote_token_mpc_dict[rt] = c 
        self.local_token_mpc_dict[lt] = c 
        self.tcpflows[tcpf] = (c, s)
        heapq.heappush(self.scheduler_heapq, (round(now_ms) + self.init_interval, c))

    def _process_mpj_event(self, mpje, *, now_ms, **kw):
        tcpf = self._get_tcpflow(mpje.flow)
        if not self._check_black_list(tcpf):
            return 
        #local->remote 
        rt = mpje.token 
        if tcpf in self.tcpflows:
            print_tcp4_flow(mpje.flow)
            raise RuntimeError("tcp flow exists!", tcpf)
        c = self.remote_token_mpc_dict[rt]
        s = c.add(tcpf, start_us = round(now_ms * 1000))
        self.tcpflows[tcpf] = (c, s)
        heapq.heappush(self.scheduler_heapq, (round(now_ms) + self.init_interval, c))

    def _process_fin_event(self, fine, **kw):
        tcpf = self._get_tcpflow(fine.flow) 
        c,_ = self.tcpflows.get(tcpf, (None, None))
        if c == None: 
            return 
        c.pop(tcpf)
        if c.empty():
            rt = c.remote_token
            lt = c.local_token
            self.remote_token_mpc_dict.pop(rt)
            self.local_token_mpc_dict.pop(lt)
    
    def _process_rm_add_addr_event(self, rm_add_addr_e, **kw):
        print("process _process_rm_add_addr_event")

        tcpf = self._get_tcpflow(rm_add_addr_e.flow) 
        c, _ = self.tcpflows.get(tcpf, (None, None))
        if c == None: 
            print_tcp4_flow(tcpf)
            raise RuntimeError("tcp flow not exists!")
        c.push_add_addr_opt(rm_add_addr_e)

    def _process_recover_add_addr_event(self, recover_add_addr_e, **kw):
        # 1.get add addr opt
        # 2.build packet using add_addr opt and recover_add_addr_e 
        # 3.send built packet to emptcpd using UNIX sock
        tcpf = self._get_tcpflow(recover_add_addr_e.flow) 
        c, f = self.tcpflows.get(tcpf, (None, None))
        if c == None: 
            raise RuntimeError("tcp flow not exists!")
        add_addr_opt_bytes = c.pop_add_addr_opt()
        if add_addr_opt_bytes != None:
            pkt = RecoverAddAddr.build_packet(add_addr_opt_bytes, recover_add_addr_e)
            pkt_bytes = raw(pkt)
            self.un_sock.send(pkt_bytes)
            #global pkt_list 
            #pkt_list.append(pkt)
            return 
        # no more add addr 
        if f.action.recover_add_addr != None and f.action.recover_add_addr == True: 
            f.action.recover_add_addr = False

        SubflowInfo.take_action(f.action, f.flow)

    def _porcess_mp_prio_backup_event(self, mp_prio_b_e, **kw):
        #store the packet 
        tcpf = self._get_tcpflow(mp_prio_b_e.flow) 
        _, f = self.tcpflows.get(tcpf, (None, None))
        if f == None: 
            raise RuntimeError("tcp flow not exists!")
        f.push_backup_pkt(mp_prio_b_e)

    def _get_tcpflow(self, tcp4):
        #tcp4tuple (local_port, remote_port, local_addr, remote_addr)
        flow = (tcp4.local_port, tcp4.remote_port, tcp4.local_addr, tcp4.remote_addr)
        return flow 
    
    def _check_black_list(self, flow):
        remote_addr = flow[3]
        local_addr = flow[2]
        
        local_list = [bytes_2_val(inet_aton("172.16.12.128")),bytes_2_val(inet_aton("172.16.12.129"))]
        remote_list = [ bytes_2_val(inet_aton("172.16.12.131")),bytes_2_val(inet_aton("172.16.12.132"))]
        #print("local: %s"int2ip(int.from_bytes(val_2_bytes(flow.local_addr, 4), byteorder = "big", signed = False)))
        if local_addr not in local_list:
            return False 
        if remote_addr not in remote_list:
            return False 

        if local_addr == 2145953984 and remote_addr == 2198605996:
            return False

        return True

# Policies 
class AddAddrPolicy(SchedulerPolixy): 
    def __init__(self, recover_time_ms):
        super().__init__()
        self.recover_time_ms = recover_time_ms
        pass 

    def make(self, emptcp_connection):
        assert(isinstance(emptcp_connection, eMPTCPConnection))
        actions = []
        now = round(time.time()*1000)
        a = eMPTCPConnection.Action()
        interval = 1000
        if now - emptcp_connection.main_flow.start_us // 1000 < self.recover_time_ms:
            #after 10 milliseconds 
            a.rm_add_addr = True 
            a.recover_add_addr = False 
            interval = self.recover_time_ms - (now - emptcp_connection.main_flow.start_us // 1000)
        else: 
            a.rm_add_addr = False
            if len(emptcp_connection.add_addr_opt_list) > 0:
                a.recover_add_addr = True 
            else:
                a.recover_add_addr = False
        actions.append((emptcp_connection.main_flow.flow, a))
        return interval, emptcp_connection.remote_token, actions

# Policies 
class SubflowPolicy(SchedulerPolixy): 
    def __init__(self, recover_flow_time_ms):
        super().__init__()
        self.recover_flow_time_ms = recover_flow_time_ms
        #  flow = (tcp4.local_port, tcp4.remote_port, tcp4.local_addr, tcp4.remote_addr)
        self.subflow_backup_list = [(sk.htonl(ip2int("172.16.12.129")),sk.htonl(ip2int("172.16.12.131"))), \
            (sk.htonl(ip2int("172.16.12.129")),sk.htonl(ip2int("172.16.12.132")))]  #local remot

    def make(self, emptcp_connection):
        assert(isinstance(emptcp_connection, eMPTCPConnection))
        actions = []
        now = round(time.time()*1000)
        a = eMPTCPConnection.Action()

        #interval = self.recover_flow_time_ms - (now - emptcp_connection.main_flow.start_us // 1000)
        interval = 20
        for info in emptcp_connection.infos():
            if (info.flow[2], info.flow[3]) not in  self.subflow_backup_list : 
                continue
            a = eMPTCPConnection.Action()
            #print(now - emptcp_connection.main_flow.start_us // 1000)
            if (now - emptcp_connection.main_flow.start_us // 1000) < self.recover_flow_time_ms :
                #set back up  
                print("set backup")
                a.backup = True 
                actions.append((info.flow, a))
            else: 
                #print("set recover")
                if info.action.backup == True :
                    print("recover")
                    a.backup = False 
                    a.recover_flow = True 
                    actions.append((info.flow, a))
        return interval, emptcp_connection.remote_token, actions
    

if __name__ == '__main__':
    '''
        setup_tc()
        SubflowInfo.setup()
        s = eMPTCPScheduler(SubflowPolicy(50))
        s.un_sock = setup_unsock()
        s.start()
        s.un_sock.close()

        for pkt in pkt_list:
            pkt.show2()
    '''
    '''
    setup_tc()
    setup_tc()
    SubflowInfo.setup()
    s = eMPTCPScheduler(TestSs())
    s.start()
    '''
